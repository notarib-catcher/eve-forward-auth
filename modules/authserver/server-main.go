package authserver

import (
	"context"
	"eve-forward-auth/modules/esiservice"
	"eve-forward-auth/types"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func NewAuthServer(logger *log.Logger, ShutdownSignal context.Context, CleanupTracker *sync.WaitGroup, EVEClient *esiservice.ESIService, Config types.Config) *AuthServer {
	return &AuthServer{
		logger:         logger,
		ShutdownSignal: ShutdownSignal,
		CleanupTracker: CleanupTracker,
		EVEClient:      EVEClient,
		config:         Config,
	}
}

func (a *AuthServer) handleChecks(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("evefa_session_token")
	if err != nil {
		http.Redirect(w, r, "http"+(If(a.config.Server.Is_Secure, "s", ""))+"://"+a.config.Server.Domain+"/login", 307)
	}
	returnedVal := a.EVEClient.VerifyUser(cookie.Value)

	if !returnedVal.Allow {
		http.SetCookie(w, &http.Cookie{
			Name:    "evefa_session_token",
			Value:   "",
			Expires: time.Now().Add(-time.Hour), // Last hour - AKA Expired cookie - deletes this immediately
			Path:    "/",
		})
		http.Redirect(w, r, "http"+(If(a.config.Server.Is_Secure, "s", ""))+"://"+a.config.Server.Domain+"/login", 307)
		return
	}

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

func staticHandler(w http.ResponseWriter, r *http.Request) {
	const staticDir = "../../static"

	urlPath := r.URL.Path

	filename := strings.TrimPrefix(urlPath, "/static/")

	if filename == "" {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	cleaned := filepath.Clean(filename)

	if strings.HasPrefix(cleaned, "..") ||
		filepath.IsAbs(cleaned) ||
		strings.ContainsRune(cleaned, 0) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	root, err := filepath.Abs(staticDir)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	fullPath, err := filepath.Abs(filepath.Join(staticDir, cleaned))
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if !strings.HasPrefix(fullPath, root+string(filepath.Separator)) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	http.ServeFile(w, r, fullPath)
}

func If[T any](cond bool, vtrue, vfalse T) T {
	if cond {
		return vtrue
	}
	return vfalse
}
