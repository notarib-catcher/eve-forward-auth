package authserver

import (
	"context"
	"eve-forward-auth/modules/esiservice"
	"eve-forward-auth/types"
	"log"
	"sync"
)

type AuthServer struct {
	logger         *log.Logger
	ShutdownSignal context.Context
	CleanupTracker *sync.WaitGroup
	EVEClient      *esiservice.ESIService
	config         types.Config
}
