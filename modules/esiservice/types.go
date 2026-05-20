package esiservice

import (
	"eve-forward-auth/types"
	"sync"
	"time"

	"github.com/antihax/goesi"
	log "github.com/charmbracelet/log"
	"golang.org/x/oauth2"
)

type ESIService struct {
	logger                 *log.Logger
	ESIClient              *goesi.APIClient
	SSOAuthenticator       *goesi.SSOAuthenticator
	ActiveAuthSessions     *AuthSessions
	ActiveLoggedInSessions *ActiveAuthenticatedSessions
	HostedAt               string
	config                 types.Config
}

type AuthSession struct {
	ExpireAt   time.Time
	RedirectTo string
}

type AuthSessions struct {
	mutex    sync.Mutex
	sessions map[string]*AuthSession
}

type ActiveAuthenticatedSession struct {
	mutex      sync.RWMutex
	token      *oauth2.Token
	Name       string
	CharID     string
	CorpID     string
	AllianceID string
	Role       string
	RefreshEVE time.Time
	RefreshDB  time.Time
}

type ActiveAuthenticatedSessions struct {
	mutex    sync.RWMutex
	sessions map[string]*ActiveAuthenticatedSession
}

type UserAuthDetails struct {
	User  string
	Uname string
	Role  string
	Allow bool
}
