package esiservice

import (
	"eve-forward-auth/modules/database"
	"eve-forward-auth/types"
	"sync"
	"time"

	"github.com/antihax/goesi"
	log "github.com/charmbracelet/log"
)

type ESIService struct {
	logger                 *log.Logger
	ESIClient              *goesi.APIClient
	SSOAuthenticator       *goesi.SSOAuthenticator
	ActiveAuthSessions     *AuthSessions
	ActiveLoggedInSessions *types.ActiveAuthenticatedSessions
	HostedAt               string
	config                 *types.Config
	databaseAPI            *database.DatabaseAPI
}

type AuthSession struct {
	ExpireAt   time.Time
	RedirectTo string
}

type AuthSessions struct {
	mutex    sync.Mutex
	sessions map[string]*AuthSession
}

type UserAuthDetails struct {
	User  string
	Uname string
	Role  string
	Allow bool
}
