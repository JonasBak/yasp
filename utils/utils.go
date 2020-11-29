package utils

const (
	LOG_MSG_PREFIX      = "LOG:"
	SETTINGS_MSG_PREFIX = "SETINGS:"
)

type SessionSettings struct {
	Traffic  bool
	Password string
}

func DefaultSettings() SessionSettings {
	return SessionSettings{
		Traffic:  true,
		Password: "",
	}
}
