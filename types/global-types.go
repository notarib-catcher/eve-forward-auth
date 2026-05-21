package types

import (
	"sync"
	"time"

	"golang.org/x/oauth2"
)

type Config struct {
	Name       string
	App_ID     string
	App_Secret string
	Port       int

	Server struct {
		Domain             string
		Base_Domain        string
		Is_Secure          bool
		Prefix             string
		User_Header        string
		UID_Header         string
		Role_Header        string
		Redirect_Whitelist []string
	}

	Overrides struct {
		Super_Admin_IDs []string
		Alliance_Allow  []string
		Corp_Allow      []string
	}

	Database struct {
		Postgres_Connection_String string
		Default_Role               string
	}
}

type ActiveAuthenticatedSession struct {
	Mutex      sync.RWMutex
	Token      *oauth2.Token
	Name       string
	CharID     string
	CorpID     string
	AllianceID string
	Role       string
	RefreshEVE time.Time
	RefreshDB  time.Time
}

type ActiveAuthenticatedSessions struct {
	Mutex    sync.RWMutex
	Sessions map[string]*ActiveAuthenticatedSession
}
