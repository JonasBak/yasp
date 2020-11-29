package main

import (
	"bufio"
	"context"
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
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var runTui = flag.Bool("tui", false, "run the client TUI")

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

func socketFileName(sessionID string) string {
	return fmt.Sprintf("/tmp/yasp-%s.sock", sessionID)
}

func logFileName(sessionID string) string {
	return fmt.Sprintf("/tmp/yasp-%s.log", sessionID)
}

type session struct {
	socket     net.Listener
	socketFile string
	pipeR      *os.File
	pipeW      *os.File
	subdomain  string

	settings utils.SessionSettings
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
	conn := ctx.Value(ssh.ContextKeyConn).(*gossh.ServerConn)

	switch req.Type {
	case "tcpip-forward":
		var reqPayload remoteForwardRequest
		if err := gossh.Unmarshal(req.Payload, &reqPayload); err != nil {
			// TODO: log parse failure
			return false, []byte{}
		}
		if srv.ReversePortForwardingCallback == nil {
			return false, []byte("port forwarding is disabled")
		}
		if !srv.ReversePortForwardingCallback(ctx, reqPayload.BindAddr, reqPayload.BindPort) {
			return false, []byte("port forwarding failed")
		}
		subdomain := reqPayload.BindAddr

		socketFile := socketFileName(sessionID)
		socket, err := net.Listen("unix", socketFile)
		if err != nil {
			// TODO: log listen failure
			return false, []byte{}
		}

		pipeR, pipeW, _ := os.Pipe()
		settings := utils.DefaultSettings()

		h.Lock()
		h.sessions[sessionID] = &session{
			socket,
			socketFile,
			pipeR,
			pipeW,
			subdomain,
			settings,
		}
		h.subdomains[subdomain] = sessionID
		h.Unlock()
		go func() {
			<-ctx.Done()
			h.Lock()
			session, ok := h.sessions[sessionID]
			if ok {
				session.socket.Close()
				session.pipeR.Close()
				session.pipeW.Close()
				os.Remove(session.socketFile)
				delete(h.sessions, sessionID)
				delete(h.subdomains, subdomain)
			}
			log.Printf("cleaned up after %s", sessionID)
			h.Unlock()
		}()

		destPort := reqPayload.BindPort

		go func() {
			for {
				c, err := socket.Accept()
				if err != nil {
					// TODO: log accept failure
					break
				}
				originAddr, orignPortStr, _ := net.SplitHostPort(c.RemoteAddr().String())
				originPort, _ := strconv.Atoi(orignPortStr)
				payload := gossh.Marshal(&remoteForwardChannelData{
					DestAddr:   reqPayload.BindAddr,
					DestPort:   uint32(destPort),
					OriginAddr: originAddr,
					OriginPort: uint32(originPort),
				})
				go func() {
					ch, reqs, err := conn.OpenChannel(forwardedTCPChannelType, payload)
					if err != nil {
						log.Println(err)
						c.Close()
						return
					}
					go gossh.DiscardRequests(reqs)
					go func() {
						defer ch.Close()
						defer c.Close()
						io.Copy(ch, c)
					}()
					go func() {
						defer ch.Close()
						defer c.Close()
						io.Copy(c, ch)
					}()
				}()
			}
		}()

		onCreate <- struct{}{}

		return true, gossh.Marshal(&remoteForwardSuccess{uint32(destPort)})

	case "cancel-tcpip-forward":
		var reqPayload remoteForwardCancelRequest
		if err := gossh.Unmarshal(req.Payload, &reqPayload); err != nil {
			// TODO: log parse failure
			return false, []byte{}
		}
		h.Lock()
		session, ok := h.sessions[sessionID]
		if ok {
			session.socket.Close()
			session.pipeR.Close()
			session.pipeW.Close()
			os.Remove(session.socketFile)
			delete(h.sessions, sessionID)
			delete(h.subdomains, session.subdomain)
		}
		h.Unlock()
		return true, nil
	default:
		return false, nil
	}
}

func (h *forwardedTCPHandler) ReversePortForwardingCallback(ctx ssh.Context, host string, port uint32) bool {
	_, exists := h.subdomains[host]
	if exists {
		return false
	}
	return true
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
			w.Header().Set("WWW-Authenticate", `Basic realm="yeet"`)
			w.WriteHeader(401)
			http.Error(w, "unauthorized", http.StatusUnauthorized)

			fmt.Fprintf(session.pipeW, "%s%s - %s %s %s - [yellow]unauthorized[white]\n", utils.LOG_MSG_PREFIX, r.RemoteAddr, r.Method, r.Host, r.URL.Path)

			return
		}
	}

	// TODO client hangson exit if there has been requests
	// context doesn't close

	httpClient := http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", session.socketFile)
			},
		},
	}

	url := fmt.Sprintf("http://%s%s", r.Host, r.RequestURI)

	proxyReq, err := http.NewRequest(r.Method, url, r.Body)

	proxyReq.Header = make(http.Header)
	for h, val := range r.Header {
		proxyReq.Header[h] = val
	}

	resp, err := httpClient.Do(proxyReq)

	fmt.Fprintf(session.pipeW, "%s%s - %s %s %s - %d\n", utils.LOG_MSG_PREFIX, r.RemoteAddr, r.Method, r.Host, r.URL.Path, resp.StatusCode)

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
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
				log.Println("could not parse last message")
			}
		}
		if err == io.EOF {
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
		Addr: ":2222",
		Handler: ssh.Handler(func(s ssh.Session) {
			ptyReq, winCh, isPty := s.Pty()
			if !isPty {
				io.WriteString(s, "No PTY requested.\n")
				s.Exit(1)
			}

			sessionID := s.Context().(ssh.Context).SessionID()
			log.Printf("started session for %s - %s", s.User(), sessionID)

			forwardHandler.Lock()
			if forwardHandler.onCreate == nil {
				forwardHandler.onCreate = make(map[string]chan struct{})
			}
			onCreate, ok := forwardHandler.onCreate[sessionID]
			if !ok {
				onCreate = make(chan struct{})
				forwardHandler.onCreate[sessionID] = onCreate
			}
			forwardHandler.Unlock()

			// TODO timeout
			<-onCreate

			session, _ := forwardHandler.sessions[sessionID]

			cmd := exec.Command(os.Args[0], "--tui", "--forward-url", session.subdomain)
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
			log.Printf("ended session for %s - %s", s.User(), sessionID)
		}),
		ReversePortForwardingCallback: ssh.ReversePortForwardingCallback(forwardHandler.ReversePortForwardingCallback),
		RequestHandlers: map[string]ssh.RequestHandler{
			"tcpip-forward":        forwardHandler.HandleSSHRequest,
			"cancel-tcpip-forward": forwardHandler.HandleSSHRequest,
		},
		PublicKeyHandler: publicKeyHandler,
		PasswordHandler:  passwordHandler,
	}

	log.Println("starting ssh server on port 2222...")

	log.Fatal(server.ListenAndServe())
}

func setWinsize(f *os.File, w, h int) {
	syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCSWINSZ),
		uintptr(unsafe.Pointer(&struct{ h, w, x, y uint16 }{uint16(h), uint16(w), 0, 0})))
}
