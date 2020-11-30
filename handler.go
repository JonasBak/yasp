package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
	"github.com/jonasbak/yasp/utils"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

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

func setWinsize(f *os.File, w, h int) {
	syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCSWINSZ),
		uintptr(unsafe.Pointer(&struct{ h, w, x, y uint16 }{uint16(h), uint16(w), 0, 0})))
}
