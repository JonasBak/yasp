package utils

const (
	LOG_MSG_PREFIX      = "LOG:"
	SETTINGS_MSG_PREFIX = "SETINGS:"
)

type SessionSettings struct {
	Block    bool
	Password string
}

func DefaultSettings() SessionSettings {
	return SessionSettings{
		Block:    false,
		Password: "",
	}
}
