package main

import (
	"bufio"
	"bytes"
	"crypto/subtle"
	"fmt"
	"github.com/jonasbak/yasp/utils"
	gossh "golang.org/x/crypto/ssh"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
)

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
