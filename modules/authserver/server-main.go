package authserver

import (
	"context"
	"eve-forward-auth/modules/esiservice"
	"eve-forward-auth/types"
	"net/http"
	"strconv"
	"sync"
	"time"

	log "github.com/charmbracelet/log"
)

func NewAuthServer(logger *log.Logger, ShutdownSignal context.Context, CleanupTracker *sync.WaitGroup, EVEClient *esiservice.ESIService, Config types.Config) *AuthServer {

	a := &AuthServer{
		logger:         logger,
		ShutdownSignal: ShutdownSignal,
		CleanupTracker: CleanupTracker,
		EVEClient:      EVEClient,
		config:         Config,
	}

	logger.Info("Setting handler functions")
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	http.HandleFunc("/dologin", a.loginHandlerWrapper)
	http.HandleFunc("/sso/callback", a.ssoCallbackWrapper)
	http.HandleFunc("/check", a.handleChecks)
	http.HandleFunc("/login", a.signinPage)
	http.Handle("/", http.RedirectHandler("/login", 302))
	logger.Info("Registered all handlers")

	return a
}

func (a *AuthServer) StartServer() {
	srv := &http.Server{
		Addr:         ":" + strconv.Itoa(a.config.Port),
		Handler:      nil,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	a.CleanupTracker.Go(func() {
		<-a.ShutdownSignal.Done()
		a.logger.Info("Closing conections...")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err := srv.Shutdown(ctx)
		if err != nil {
			a.logger.Error("Server shutdown timeout exceeded!", "error", err)
			err = srv.Close()
			if err != nil {
				a.logger.Error("Server close has errored!", "error", err)
			}
		}
		a.logger.Info("Server closed")
	})

	a.logger.Info("Starting server", "port", a.config.Port)

	err := srv.ListenAndServe()
	if err != nil {
		a.logger.Warn("Server exited!")
	}
}

func (a *AuthServer) handleChecks(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("evefa_session_token")
	if err != nil {
		http.Redirect(w, r, "http"+(If(a.config.Server.Is_Secure, "s", ""))+"://"+a.config.Server.Domain+"/login", 302)
		return
	}

	returnedVal := a.EVEClient.VerifyUser(cookie.Value, false)

	if !returnedVal.Allow {
		a.logger.Debug("CHECK RETURNED DISALLOW", "User", returnedVal.User, "UID", returnedVal.Uname)

		http.SetCookie(w, &http.Cookie{
			Name:    "evefa_session_token",
			Value:   "",
			Expires: time.Now().Add(-time.Hour), // Last hour - AKA Expired cookie - deletes this immediately
			Path:    "/",
		})
		w.Header().Add("Content-Type", "")
		http.Redirect(w, r, "http"+(If(a.config.Server.Is_Secure, "s", ""))+"://"+a.config.Server.Domain+"/login", 307)
		return
	}

	a.logger.Debug("CHECK OK 200 ALLOW", "User", returnedVal.User, "UID", returnedVal.Uname)

	w.Header().Add(a.config.Server.User_Header, returnedVal.Uname)
	w.Header().Add(a.config.Server.UID_Header, returnedVal.User)
	w.Header().Add(a.config.Server.Role_Header, returnedVal.Role)
	w.WriteHeader(200)

}

func (a *AuthServer) loginHandlerWrapper(w http.ResponseWriter, r *http.Request) {
	a.EVEClient.HandleIncomingAuth(w, r)
}

func (a *AuthServer) ssoCallbackWrapper(w http.ResponseWriter, r *http.Request) {
	a.EVEClient.HandleAfterSSO(w, r)
}

func (s *AuthServer) signinPage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "templates/signin.html")
}

func If[T any](cond bool, vtrue, vfalse T) T {
	if cond {
		return vtrue
	}
	return vfalse
}
