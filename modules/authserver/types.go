package authserver

import (
	"context"
	"eve-forward-auth/modules/esiservice"
	"eve-forward-auth/types"
	"sync"

	log "github.com/charmbracelet/log"
)

type AuthServer struct {
	logger         *log.Logger
	ShutdownSignal context.Context
	CleanupTracker *sync.WaitGroup
	EVEClient      *esiservice.ESIService
	config         types.Config
}
