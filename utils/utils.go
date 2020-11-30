package utils

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
	return SessionSettings{
		Subdomain: subdomain,
		Block:     false,
		Password:  "",
	}
}

func DefaultSettings() SessionSettings {
	return SessionSettings{
		Subdomain: "",
		Block:     false,
		Password:  "",
	}
}
