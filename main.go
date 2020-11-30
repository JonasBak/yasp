package main

import (
	"flag"
	"github.com/gliderlabs/ssh"
	"github.com/jonasbak/yasp/tui"
	"log"
	"net/http"
	"os"
	"regexp"
	"time"
)

var runTui = flag.Bool("tui", false, "run the client TUI")
var colorRegex = regexp.MustCompile(`\[(.+?)\]`)

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
