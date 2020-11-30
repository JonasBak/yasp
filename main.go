package main

import (
	"bufio"
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
	"github.com/jonasbak/yasp/tui"
	"github.com/jonasbak/yasp/utils"
	gossh "golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
	"unsafe"
)

var runTui = flag.Bool("tui", false, "run the client TUI")
var colorRegex = regexp.MustCompile(`\[(.+?)\]`)

const (
	forwardedTCPChannelType = "forwarded-tcpip"
)

type remoteForwardRequest struct {
	BindAddr string
	BindPort uint32
}

type remoteForwardSuccess struct {
	BindPort uint32
}

type remoteForwardCancelRequest struct {
	BindAddr string
	BindPort uint32
}

type remoteForwardChannelData struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

type session struct {
	conn  *gossh.ServerConn
	pipeR *os.File
	pipeW *os.File

	settings utils.SessionSettings

	errors []error
}

func (s *session) pushError(err error) {
	s.errors = append(s.errors, err)
}

type forwardedTCPHandler struct {
	sync.Mutex
	sessions   map[string]*session
	subdomains map[string]string
	onCreate   map[string]chan struct{}
}

func (h *forwardedTCPHandler) HandleSSHRequest(ctx ssh.Context, srv *ssh.Server, req *gossh.Request) (bool, []byte) {
	sessionID := ctx.SessionID()

	h.Lock()
	if h.sessions == nil {
		h.sessions = make(map[string]*session)
	}
	if h.subdomains == nil {
		h.subdomains = make(map[string]string)
	}
	if h.onCreate == nil {
		h.onCreate = make(map[string]chan struct{})
	}
	onCreate, ok := h.onCreate[sessionID]
	if !ok {
		onCreate = make(chan struct{})
		h.onCreate[sessionID] = onCreate
	}
	h.Unlock()

	defer func() { onCreate <- struct{}{} }()

	conn := ctx.Value(ssh.ContextKeyConn).(*gossh.ServerConn)

	switch req.Type {
	case "tcpip-forward":
		var reqPayload remoteForwardRequest
		if err := gossh.Unmarshal(req.Payload, &reqPayload); err != nil {
			// TODO: log parse failure
			return false, []byte{}
		}

		subdomain := reqPayload.BindAddr

		pipeR, pipeW, _ := os.Pipe()

		settings := utils.DefaultSettingsWithSubdomain(subdomain)

		go func() {
			<-ctx.Done()
			h.Lock()
			session, ok := h.sessions[sessionID]
			if ok {
				session.pipeR.Close()
				session.pipeW.Close()
				delete(h.sessions, sessionID)
				delete(h.onCreate, sessionID)
				subdomainSession, ok := h.subdomains[session.settings.Subdomain]
				if ok && subdomainSession == sessionID {
					delete(h.subdomains, session.settings.Subdomain)
				}
			}
			log.Printf("cleaned up after %s", sessionID)
			h.Unlock()
		}()

		h.Lock()
		defer h.Unlock()

		s := session{
			conn,
			pipeR,
			pipeW,
			settings,
			[]error{},
		}

		h.sessions[sessionID] = &s

		if err := h.ReversePortForwardingCallback(ctx, subdomain, reqPayload.BindPort); err != nil {
			s.pushError(err)
			return false, []byte("port forwarding failed")
		}

		h.subdomains[subdomain] = sessionID

		return true, gossh.Marshal(&remoteForwardSuccess{reqPayload.BindPort})

	case "cancel-tcpip-forward":
		var reqPayload remoteForwardCancelRequest
		if err := gossh.Unmarshal(req.Payload, &reqPayload); err != nil {
			// TODO: log parse failure
			return false, []byte{}
		}
		h.Lock()
		session, ok := h.sessions[sessionID]
		if ok {
			session.pipeR.Close()
			session.pipeW.Close()
			delete(h.sessions, sessionID)
			delete(h.onCreate, sessionID)
			subdomainSession, ok := h.subdomains[session.settings.Subdomain]
			if ok && subdomainSession == sessionID {
				delete(h.subdomains, session.settings.Subdomain)
			}
		}
		h.Unlock()
		return true, nil
	default:
		return false, nil
	}
}

func (h *forwardedTCPHandler) ReversePortForwardingCallback(ctx ssh.Context, subdomain string, port uint32) error {
	if port != 80 {
		return fmt.Errorf("Port must be 80 for http forwarding")
	}

	for _, r := range subdomain {
		if !unicode.IsLetter(r) {
			return fmt.Errorf("Subdomain can only contain letters")
		}
	}
	_, exists := h.subdomains[subdomain]
	if exists {
		return fmt.Errorf("Subdomain '%s' already taken", subdomain)
	}
	return nil
}

func (h *forwardedTCPHandler) httpMuxHandler(w http.ResponseWriter, r *http.Request) {
	subdomain := strings.Split(r.Host, ".")[0]
	h.Lock()
	sessionID, ok := h.subdomains[subdomain]
	var session *session = nil
	if ok {
		s, _ := h.sessions[sessionID]
		session = s
	}
	h.Unlock()

	if session == nil {
		http.Error(w, fmt.Sprintf("no session on subdomain '%s'", subdomain), http.StatusNotFound)
		return
	}

	if session.settings.Block {
		http.Error(w, "session has blocked traffic", http.StatusForbidden)

		fmt.Fprintf(session.pipeW, "%s%s - %s %s %s - [red]blocked[white]\n", utils.LOG_MSG_PREFIX, r.RemoteAddr, r.Method, r.Host, r.URL.Path)

		return
	}

	if correctPass := session.settings.Password; len(correctPass) > 0 {
		user, pass, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(user), []byte("yasp")) != 1 || subtle.ConstantTimeCompare([]byte(pass), []byte(correctPass)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="Authentication is enabled for this session"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)

			fmt.Fprintf(session.pipeW, "%s%s - %s %s %s - [yellow]unauthorized[white]\n", utils.LOG_MSG_PREFIX, r.RemoteAddr, r.Method, r.Host, r.URL.Path)

			return
		}
	}

	originAddr, orignPortStr, _ := net.SplitHostPort(r.RemoteAddr)
	originPort, _ := strconv.Atoi(orignPortStr)
	payload := gossh.Marshal(&remoteForwardChannelData{
		DestAddr:   session.settings.Subdomain,
		DestPort:   uint32(80),
		OriginAddr: originAddr,
		OriginPort: uint32(originPort),
	})

	ch, reqs, err := session.conn.OpenChannel(forwardedTCPChannelType, payload)
	if err != nil {
		http.Error(w, "could not connect to upstream", http.StatusBadGateway)

		fmt.Fprintf(session.pipeW, "%s[red]ERROR[white] upstream: %s\n", utils.LOG_MSG_PREFIX, err.Error())

		return
	}
	defer ch.Close()

	go gossh.DiscardRequests(reqs)

	go func() {
		dump, _ := httputil.DumpRequest(r, true)
		buf := bytes.NewReader(dump)
		io.Copy(ch, buf)
	}()

	buf := bufio.NewReader(ch)
	resp, err := http.ReadResponse(buf, r)
	if err != nil {
		http.Error(w, "could not parse upstream", http.StatusBadGateway)

		fmt.Fprintf(session.pipeW, "%s[red]ERROR[white] upstream: %s\n", utils.LOG_MSG_PREFIX, err.Error())

		return
	}

	fmt.Fprintf(session.pipeW, "%s%s - %s %s %s - %d\n", utils.LOG_MSG_PREFIX, r.RemoteAddr, r.Method, r.Host, r.URL.Path, resp.StatusCode)

	for h, vals := range resp.Header {
		for _, val := range vals {
			w.Header().Add(h, val)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (h *forwardedTCPHandler) sshHandler(s ssh.Session) {
	serviceURL := os.Getenv("SERVICE_URL")
	if serviceURL == "" {
		serviceURL = "localhost:8080"
	}

	ptyReq, winCh, isPty := s.Pty()

	sessionID := s.Context().(ssh.Context).SessionID()
	log.Printf("started session for %s - %s", s.User(), sessionID)
	defer log.Printf("ended session for %s - %s", s.User(), sessionID)

	h.Lock()
	if h.onCreate == nil {
		h.onCreate = make(map[string]chan struct{})
	}
	onCreate, ok := h.onCreate[sessionID]
	if !ok {
		onCreate = make(chan struct{})
		h.onCreate[sessionID] = onCreate
	}
	h.Unlock()

	// TODO timeout
	<-onCreate

	session, _ := h.sessions[sessionID]

	if s, err := utils.ParseSettings(session.settings, isPty, s.Command()); err != nil {
		session.pushError(err)
	} else {
		session.settings = s
	}

	if len(session.errors) > 0 {
		fmt.Fprintln(s, "Failed to connect:")
		for _, err := range session.errors {
			fmt.Fprintln(s, err.Error())
		}
		s.Exit(1)
		return
	}

	if !isPty {
		fmt.Fprintf(s, "Sharing connection on: %s.%s\n", session.settings.Subdomain, serviceURL)
		if len(session.settings.Password) > 0 {
			fmt.Fprintf(s, "Using password authentication\n")
		}
		fmt.Fprintf(s, "Request log:\n")
		readLog(session.pipeR, func(log string) {
			fmt.Fprintf(s, colorRegex.ReplaceAllString(log, ""))
		})
		return
	}

	cmd := exec.Command(os.Args[0], "--tui", "--service-url", serviceURL)
	cmd.ExtraFiles = []*os.File{
		session.pipeR,
	}
	cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
	stderr, err := cmd.StderrPipe()
	if err != nil {
		panic(err)
	}
	f, err := pty.Start(cmd)
	if err != nil {
		panic(err)
	}

	writeSettings := func() {
		settingsStr, _ := json.Marshal(session.settings)
		fmt.Fprintf(session.pipeW, "%s%s\n", utils.SETTINGS_MSG_PREFIX, settingsStr)
	}

	go writeSettings()
	go readMessages(stderr, func(s utils.SessionSettings) {
		session.settings = s
		writeSettings()
	})
	go func() {
		for win := range winCh {
			setWinsize(f, win.Width, win.Height)
		}
	}()
	go func() {
		io.Copy(f, s) // stdin
	}()
	io.Copy(s, f) // stdout
	s.Exit(0)
}

func getPublicKeyHandler() ssh.PublicKeyHandler {
	authorizedKeysDir := os.Getenv("AUTHORIZED_KEYS_DIR")
	if authorizedKeysDir == "" {
		return nil
	}

	authorizedKeysFiles, err := ioutil.ReadDir(authorizedKeysDir)
	if err != nil {
		panic(err)
	}
	authorizedUsersKeys := make(map[string][]ssh.PublicKey)

	for _, file := range authorizedKeysFiles {
		user := file.Name()
		keys := []ssh.PublicKey{}

		file, err := os.Open(fmt.Sprintf("%s/%s", authorizedKeysDir, user))
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			key, _, _, _, err := ssh.ParseAuthorizedKey(scanner.Bytes())
			if err != nil {
				panic(err)
			}
			keys = append(keys, key)
		}

		if err := scanner.Err(); err != nil {
			log.Fatal(err)
		}

		authorizedUsersKeys[user] = keys
	}
	return func(ctx ssh.Context, key ssh.PublicKey) bool {
		user := ctx.User()
		log.Printf("user '%s' attempting to connect with authorized key", user)
		keys, ok := authorizedUsersKeys[user]
		if !ok {
			keys = []ssh.PublicKey{}
		}
		authorized := false
		for _, authKey := range keys {
			if ssh.KeysEqual(key, authKey) {
				authorized = true
				break
			}
		}
		log.Printf("user '%s' authorized: %t", user, authorized)
		return authorized
	}
}

func getPasswordHandler() ssh.PasswordHandler {
	adminPassword := os.Getenv("ADMIN_PASSWORD")
	if adminPassword == "" {
		return nil
	}
	return func(ctx ssh.Context, password string) bool {
		user := ctx.User()
		log.Printf("user '%s' attempting to connect with password", user)
		authorized := adminPassword == password
		log.Printf("user '%s' authorized: %t", user, authorized)
		return authorized
	}
}

func readMessages(stderr io.ReadCloser, setSettings func(utils.SessionSettings)) {
	r := bufio.NewReader(stderr)
	for {
		line, err := r.ReadBytes('\n')
		if err != nil && err != io.EOF {
			panic(err)
		}
		if len(line) > 0 {
			lineStr := string(line)
			if strings.HasPrefix(lineStr, utils.SETTINGS_MSG_PREFIX) {
				settings := utils.SessionSettings{}
				err := json.Unmarshal(line[len(utils.SETTINGS_MSG_PREFIX):], &settings)
				if err != nil {
					log.Println("could not parse settings")
				} else {
					setSettings(settings)
				}
			} else {
				log.Printf("could not parse last message: %s", lineStr)
			}
		}
		if err == io.EOF {
			return
		}
	}
}

func readLog(pipe io.ReadCloser, pushLog func(string)) {
	r := bufio.NewReader(pipe)
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			lineStr := string(line)
			if strings.HasPrefix(lineStr, utils.LOG_MSG_PREFIX) {
				pushLog(lineStr[len(utils.LOG_MSG_PREFIX):])
			} else {
				log.Printf("could not parse last message: %s", lineStr)
			}
		}
		if err != nil {
			return
		}
	}
}

func main() {
	flag.Parse()
	if *runTui {
		tui.Run()
		return
	}

	keyLocation := os.Getenv("KEY_LOCATION")

	publicKeyHandler := getPublicKeyHandler()
	passwordHandler := getPasswordHandler()

	log.Printf("using public key auth: %t", publicKeyHandler != nil)
	log.Printf("using password auth: %t", passwordHandler != nil)
	if publicKeyHandler == nil && passwordHandler == nil {
		log.Println("WARNING: not using auth")
	}

	forwardHandler := &forwardedTCPHandler{}

	s := &http.Server{
		Addr:           ":8080",
		Handler:        http.HandlerFunc(forwardHandler.httpMuxHandler),
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	go func() {
		log.Println("starting http server on port 8080...")

		log.Fatal(s.ListenAndServe())
	}()

	server := ssh.Server{
		Addr:    ":2222",
		Handler: ssh.Handler(forwardHandler.sshHandler),
		RequestHandlers: map[string]ssh.RequestHandler{
			"tcpip-forward":        forwardHandler.HandleSSHRequest,
			"cancel-tcpip-forward": forwardHandler.HandleSSHRequest,
		},
		PublicKeyHandler: publicKeyHandler,
		PasswordHandler:  passwordHandler,
	}

	if keyLocation == "" {
		log.Println("No key location specified, creating new...")
	} else {
		if _, err := os.Stat(keyLocation); err == nil {
			server.SetOption(ssh.HostKeyFile(keyLocation))
		} else {
			log.Println("Key location specified but no key found, creating new...")
		}
	}

	log.Println("starting ssh server on port 2222...")

	log.Fatal(server.ListenAndServe())
}

func setWinsize(f *os.File, w, h int) {
	syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCSWINSZ),
		uintptr(unsafe.Pointer(&struct{ h, w, x, y uint16 }{uint16(h), uint16(w), 0, 0})))
}
