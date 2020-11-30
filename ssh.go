package main

import (
	"bufio"
	"fmt"
	"github.com/gliderlabs/ssh"
	"github.com/jonasbak/yasp/utils"
	gossh "golang.org/x/crypto/ssh"
	"io/ioutil"
	"log"
	"os"
	"sync"
	"unicode"
)

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
