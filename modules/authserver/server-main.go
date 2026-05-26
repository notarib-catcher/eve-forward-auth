package authserver

import (
	"context"
	"eve-forward-auth/modules/esiservice"
	"eve-forward-auth/types"
	"net/http"
	"net/url"
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
	http.HandleFunc("/forbidden", a.forbiddenPage)
	http.HandleFunc("/success", a.successPage)
	http.HandleFunc("/logout", a.logout)
	http.HandleFunc("/purge", a.purge)
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

	ogUrl := getOriginalURL(r)
	a.logger.Debug("Got original URL", "og", ogUrl)

	if !isValidUrl(ogUrl) {
		a.logger.Debug("Invalid original URL, setting empty", "og", ogUrl)
		//set to empty, this way
		ogUrl = ""
	}

	if err != nil {
		http.Redirect(w, r, "http"+(If(a.config.Server.Is_Secure, "s", ""))+"://"+a.config.Server.Domain+"/login?redirect="+ogUrl, 302)
		return
	}

	returnedVal := a.EVEClient.VerifyUser(cookie.Value, false)

	if !returnedVal.Allow {
		w.Header().Add("Content-Type", "")
		http.Redirect(w, r, "http"+(If(a.config.Server.Is_Secure, "s", ""))+"://"+a.config.Server.Domain+"/forbidden?nocookie=false&redirect="+ogUrl, 307)
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

func (s *AuthServer) forbiddenPage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "templates/forbidden.html")
}

func (s *AuthServer) successPage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "templates/success.html")
}

func (s *AuthServer) logout(w http.ResponseWriter, r *http.Request) {
	redirectURL := r.URL.Query().Get("redirect")

	if redirectURL == "" {
		redirectURL = "/success"
	}

	cookie, err := r.Cookie("evefa_session_token")

	if err == nil {
		s.EVEClient.DatabaseAPI.Fetch(cookie.Value, false)
		http.SetCookie(w, &http.Cookie{
			Name:    "evefa_session_token",
			Domain:  s.config.Server.Base_Domain,
			Value:   "",
			Expires: time.Now().Add(-180 * 24 * time.Hour), // 6 months in the past AKA expire NOW
			Path:    "/",
		})
		s.EVEClient.DatabaseAPI.Delete(cookie.Value)
	}

	http.Redirect(w, r, "/login?redirect="+redirectURL, http.StatusFound)
}

func (s *AuthServer) purge(w http.ResponseWriter, r *http.Request) {
	redirectURL := r.URL.Query().Get("redirect")

	if redirectURL == "" {
		redirectURL = "/success"
	}

	cookie, err := r.Cookie("evefa_session_token")

	if err == nil {
		s.EVEClient.DatabaseAPI.Fetch(cookie.Value, false)
		http.SetCookie(w, &http.Cookie{
			Name:    "evefa_session_token",
			Domain:  s.config.Server.Base_Domain,
			Value:   "",
			Expires: time.Now().Add(-180 * 24 * time.Hour), // 6 months in the past AKA expire NOW
			Path:    "/",
		})
		s.EVEClient.DatabaseAPI.Purge(cookie.Value)
	}

	http.Redirect(w, r, "/login?redirect="+redirectURL, http.StatusFound)
}

func If[T any](cond bool, vtrue, vfalse T) T {
	if cond {
		return vtrue
	}
	return vfalse
}

func getOriginalURL(r *http.Request) string {
	proto := firstNonEmpty(
		r.Header.Get("X-Forwarded-Proto"),
		r.Header.Get("X-Scheme"),
		"https",
	)
	host := firstNonEmpty(
		r.Header.Get("X-Forwarded-Host"),
		r.Header.Get("X-Original-Host"),
		r.Host,
	)
	uri := firstNonEmpty(
		r.Header.Get("X-Forwarded-Uri"),
		r.Header.Get("X-Original-URL"),
		r.Header.Get("X-Original-Uri"),
		r.URL.RequestURI(),
	)

	return proto + "://" + host + uri
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func isValidUrl(toTest string) bool {
	_, err := url.ParseRequestURI(toTest)
	if err != nil {
		return false
	}
	u, err := url.Parse(toTest)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	return true
}
