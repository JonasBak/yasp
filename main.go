package main

import (
	"context"
	"fmt"
	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
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

func socketFileName(sessionID string) string {
	return fmt.Sprintf("/tmp/yasp-%s", sessionID)
}

type session struct {
	ln         net.Listener
	socketFile string
	subdomain  string
}

type forwardedTCPHandler struct {
	forwards   map[string]session
	subdomains map[string]string
	sync.Mutex
}

func (h *forwardedTCPHandler) HandleSSHRequest(ctx ssh.Context, srv *ssh.Server, req *gossh.Request) (bool, []byte) {
	h.Lock()
	if h.forwards == nil {
		h.forwards = make(map[string]session)
	}
	if h.subdomains == nil {
		h.subdomains = make(map[string]string)
	}
	h.Unlock()
	conn := ctx.Value(ssh.ContextKeyConn).(*gossh.ServerConn)

	sessionID := ctx.SessionID()

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
		ln, err := net.Listen("unix", socketFile)
		if err != nil {
			// TODO: log listen failure
			return false, []byte{}
		}

		destPort := reqPayload.BindPort

		h.Lock()
		h.forwards[sessionID] = session{
			ln,
			socketFile,
			subdomain,
		}
		h.subdomains[subdomain] = sessionID
		h.Unlock()
		go func() {
			<-ctx.Done()
			h.Lock()
			session, ok := h.forwards[sessionID]
			if ok {
				delete(h.subdomains, sessionID)
			}
			h.Unlock()
			if ok {
				session.ln.Close()
				os.Remove(session.socketFile)
			}
		}()
		go func() {
			for {
				c, err := ln.Accept()
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
						// TODO: log failure to open channel
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
			h.Lock()
			delete(h.forwards, sessionID)
			h.Unlock()
		}()
		return true, gossh.Marshal(&remoteForwardSuccess{uint32(destPort)})

	case "cancel-tcpip-forward":
		var reqPayload remoteForwardCancelRequest
		if err := gossh.Unmarshal(req.Payload, &reqPayload); err != nil {
			// TODO: log parse failure
			return false, []byte{}
		}
		h.Lock()
		session, ok := h.forwards[sessionID]
		if ok {
			delete(h.subdomains, sessionID)
		}
		h.Unlock()
		if ok {
			session.ln.Close()
			os.Remove(session.socketFile)
		}
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
		s, _ := h.forwards[sessionID]
		session = &s
	}
	h.Unlock()

	if session == nil {
		http.Error(w, fmt.Sprintf("no session on subdomain '%s'", subdomain), http.StatusNotFound)
		return
	}

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
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}

func main() {
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
			io.WriteString(s, "Remote forwarding available...\n")
			select {}
		}),
		ReversePortForwardingCallback: ssh.ReversePortForwardingCallback(forwardHandler.ReversePortForwardingCallback),
		RequestHandlers: map[string]ssh.RequestHandler{
			"tcpip-forward":        forwardHandler.HandleSSHRequest,
			"cancel-tcpip-forward": forwardHandler.HandleSSHRequest,
		},
	}

	log.Println("starting ssh server on port 2222...")

	log.Fatal(server.ListenAndServe())
}
