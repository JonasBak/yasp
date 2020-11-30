package utils

import (
	"fmt"
	"strings"
)

const (
	LOG_MSG_PREFIX      = "LOG:"
	SETTINGS_MSG_PREFIX = "SETINGS:"
)

type SessionSettings struct {
	Subdomain string
	Block     bool
	Password  string
}

func DefaultSettingsWithSubdomain(subdomain string) SessionSettings {
	s := DefaultSettings()
	s.Subdomain = subdomain
	return s
}

func DefaultSettings() SessionSettings {
	return SessionSettings{
		Subdomain: "",
		Block:     true,
		Password:  "",
	}
}

func ParseSettings(initial SessionSettings, pty bool, cmd []string) (SessionSettings, error) {

	for _, c := range cmd {
		c = strings.Trim(c, " ")
		if len(c) == 0 {
			continue
		}
		if strings.HasPrefix(c, "pass=") {
			initial.Password = c[5:]
		} else {
			switch c {
			case "block":
				initial.Block = true
			case "noblock", "open":
				initial.Block = false
			default:
				return initial, fmt.Errorf("could not parse command '%s'", c)
			}
		}
	}

	if !pty {
		initial.Block = false
	}

	return initial, nil
}
