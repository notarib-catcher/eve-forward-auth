package main

import (
	"context"
	"eve-forward-auth/modules/authserver"
	"eve-forward-auth/modules/database"
	"eve-forward-auth/modules/esiservice"
	"eve-forward-auth/types"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/charmbracelet/log"
	"github.com/pelletier/go-toml/v2"
)

func main() {
	log.SetPrefix("CORE")
	log.Info("FORWARD AUTH SERVER STARTING", "version", Project_version, "go", runtime.Version())
	wd, err := os.Getwd()
	if err != nil {
		log.Fatal("os.Getwd failed", "error", err)
	}
	log.Info("at "+time.Now().Local().String(), "in", wd)
	configBytes, err := os.ReadFile("./config.toml")
	if err != nil {
		log.Fatal("Could not read config.toml", err)
	}

	var config types.Config

	err = toml.Unmarshal(configBytes, &config)
	if err != nil {
		log.Fatal("Could not parse config.toml", err)
	}

	hostedAt := If(config.Server.Is_Secure, "https://", "http://") + config.Server.Domain + "/" + (If(config.Server.Prefix != "", config.Server.Prefix+"/", ""))

	log.Info("Loaded config",
		"name", config.Name,
		"hosted at", hostedAt)

	log.Debug("Setting up thread termination")

	waitForCleanup := sync.WaitGroup{}
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	ctxExit, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	ctxStop, cancel := context.WithCancel(context.Background())
	defer stop()

	go func() {
		<-ctxExit.Done()
		println()
		log.Info("Received Interrupt")
		cancel()
	}()

	log.Info("Starting services")
	sessions := types.ActiveAuthenticatedSessions{
		Mutex:    sync.RWMutex{},
		Sessions: make(map[string]*types.ActiveAuthenticatedSession),
	}
	loggerDB := log.New(os.Stdout)
	loggerDB.SetPrefix("[DBService]")
	loggerDB.SetReportTimestamp(true)
	loggerDB.SetLevel(log.DebugLevel)
	loggerESI := log.New(os.Stdout)
	loggerESI.SetPrefix("[ESIService]")
	loggerESI.SetReportTimestamp(true)
	loggerESI.SetLevel(log.DebugLevel)
	loggerAuth := log.New(os.Stdout)
	loggerAuth.SetPrefix("[Server]")
	loggerAuth.SetReportTimestamp(true)
	loggerAuth.SetLevel(log.DebugLevel)

	DB := database.NewDB(loggerDB, ctxStop, &waitForCleanup, &sessions, &config)

	ESI := esiservice.NewESIService(loggerESI, hostedAt, hostedAt+"sso/callback", &sessions, &config, DB)

	Server := authserver.NewAuthServer(loggerAuth, ctxStop, &waitForCleanup, ESI, config)
	log.Info("Initialisation complete!")
	Server.StartServer() //This SHOULD block

	<-ctxExit.Done() //Just incase the previous function errored, we block here until an interrupt

	cancel()

	closeCompleted := make(chan int, 1)

	go func() {
		waitForCleanup.Wait()
		closeCompleted <- 1
	}()

	ctx, cancel2 := context.WithTimeout(context.Background(), time.Second*12)
	defer cancel2()
	select {
	case <-closeCompleted:
		log.Info("All services have been shutdown. Exiting...")
	case <-ctx.Done():
		log.Warn("Close timeout exceeded. Terminating...")
	}
}

// TERNARY SUPPORT ?
func If[T any](cond bool, vtrue, vfalse T) T {
	if cond {
		return vtrue
	}
	return vfalse
}
