package database

import (
	"context"
	"log"
	"sync"
)

type DatabaseAPI struct {
	logger         *log.Logger
	ShutdownSignal context.Context
	CleanupTracker *sync.WaitGroup
}
