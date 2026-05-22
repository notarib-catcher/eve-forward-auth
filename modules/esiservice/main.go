package esiservice

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"eve-forward-auth/modules/database"
	"eve-forward-auth/types"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/antihax/goesi"
	log "github.com/charmbracelet/log"
)

var scopes = []string{"publicData"}
var preventDoS = make(map[string]struct{})

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

func NewESIService(logger *log.Logger, HostedAt string, Redirect_URL string, Sessions *types.ActiveAuthenticatedSessions, Config *types.Config, DBAPI *database.DatabaseAPI) *ESIService {

	nonCachingClient := &http.DefaultClient
	auth := goesi.NewSSOAuthenticatorV2(*nonCachingClient, Config.App_ID, Config.App_Secret, Redirect_URL, scopes)

	logger.Info("Initialized ESI handler")
	return &ESIService{
		logger:           logger,
		SSOAuthenticator: auth,
		ActiveAuthSessions: &AuthSessions{
			sessions: make(map[string]*AuthSession),
			mutex:    sync.Mutex{},
		},
		HostedAt:               HostedAt,
		ActiveLoggedInSessions: Sessions,
		config:                 Config,
		databaseAPI:            DBAPI,
	}
}

func (es *ESIService) HandleIncomingAuth(w http.ResponseWriter, r *http.Request) {

	redirect := r.URL.Query().Get("redirect")

	if !isValidUrl(redirect) {
		es.logger.Warn("Redirect URL is not valid, setting as /success page on auth", "was originally", redirect)
		redirect = es.HostedAt + "/success"
	}

	allowed := false

	if redirect == es.HostedAt+"/success" {
		allowed = true
	}

	// If redirect URL is not a valid whitelisted URL, we cannot allow a redirect to it post-authentication
	for _, url := range es.config.Server.Redirect_Whitelist {
		if redirect == url {
			allowed = true
			break
		}
	}

	if !allowed {
		es.logger.Error("Redirect URL not valid, rejecting request", "provided", redirect)
		http.Redirect(w, r, es.HostedAt+"login", http.StatusExpectationFailed)
		return
	}

	// Generate State Cookie
	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)

	session := &AuthSession{
		ExpireAt:   time.Now().Add(5 * time.Minute),
		RedirectTo: redirect,
	}

	es.ActiveAuthSessions.mutex.Lock()
	es.ActiveAuthSessions.sessions[state] = session
	es.ActiveAuthSessions.mutex.Unlock()

	es.logger.Debug("Creating new session", "state", state, "redirect to", redirect, "expires at", session.ExpireAt)

	url := es.SSOAuthenticator.AuthorizeURL(state, true, scopes)

	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (es *ESIService) HandleAfterSSO(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	state := r.FormValue("state")

	es.ActiveAuthSessions.mutex.Lock()

	if es.ActiveAuthSessions.sessions[state] == nil {
		es.ActiveAuthSessions.mutex.Unlock()
		es.logger.Error("Invalid state", "provided", state)
		http.Redirect(w, r, es.HostedAt+"login", http.StatusBadRequest)
		return
	}

	if time.Now().After(es.ActiveAuthSessions.sessions[state].ExpireAt) {
		es.logger.Error("State expired", "provided", state, "expired at", es.ActiveAuthSessions.sessions[state].ExpireAt)
		es.ActiveAuthSessions.mutex.Unlock()
		http.Redirect(w, r, es.HostedAt+"login", http.StatusBadRequest)
		return
	}

	redirect := es.ActiveAuthSessions.sessions[state].RedirectTo
	delete(es.ActiveAuthSessions.sessions, state)
	es.ActiveAuthSessions.mutex.Unlock()

	token, err := es.SSOAuthenticator.TokenExchange(code)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Error confirming login with EVE Servers"))
		return
	}

	b := make([]byte, 64)
	rand.Read(b)
	SessionCookie := base64.URLEncoding.EncodeToString(b)

	NewSession := &types.ActiveAuthenticatedSession{
		Token:      token,
		Mutex:      sync.RWMutex{},
		RefreshDB:  time.Now(),
		RefreshEVE: time.Now(),
	}

	err = es.UpdateEVEInfo(NewSession, true, "")

	if err != nil {
		es.logger.Error("Error while updating info from ESI", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Error fetching info from ESI"))

		if err.Error() == "Token Validation Error" {
			es.logger.Debug("Token Invalid")
		}
		return
	}

	es.ActiveLoggedInSessions.Mutex.Lock()
	es.ActiveLoggedInSessions.Sessions[SessionCookie] = NewSession
	es.ActiveLoggedInSessions.Mutex.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:    "evefa_session_token",
		Domain:  es.config.Server.Base_Domain,
		Value:   SessionCookie,
		Expires: time.Now().Add(180 * 24 * time.Hour), // 6 months
		Path:    "/",
	})

	es.databaseAPI.SyncMemory(SessionCookie, true)

	http.Redirect(w, r, "http"+(If(es.config.Server.Is_Secure, "s", ""))+"://"+es.config.Server.Domain+"/"+es.config.Server.Prefix+"/success?redirect="+redirect, 200)
}

func (es *ESIService) UpdateEVEInfo(StoredSession *types.ActiveAuthenticatedSession, force bool, optionalCookie string) error {

	StoredSession.Mutex.Lock()
	defer StoredSession.Mutex.Unlock()
	if !force {
		if time.Now().Before(StoredSession.RefreshEVE) {
			es.logger.Debug("Skipping ESI fetch")
			return nil
		}
	}

	es.logger.Debug("Doing ESI fetch...")

	StoredToken := *StoredSession.Token
	tokenSrc := es.SSOAuthenticator.TokenSource(&StoredToken)
	claims, err := es.SSOAuthenticator.Verify(tokenSrc)

	if err != nil {
		return err
	}

	res, err := http.Get("https://esi.evetech.net/characters/" + strconv.Itoa(int(claims.CharacterID)))
	if err != nil {
		es.logger.Error("ESI Public Fetch Error", "CharID", claims.CharacterID, "error", err)
		return errors.New(("ESI Public Fetch Error"))
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}

	type extractInfo struct {
		CorpID     int `json:"corporation_id"`
		AllianceID int `json:"alliance_id"`
	}

	var result extractInfo
	err = json.Unmarshal(body, &result)
	if err != nil {
		return err
	}

	AllianceID := strconv.Itoa(result.AllianceID)
	CorporationID := strconv.Itoa(result.CorpID)
	token, err := tokenSrc.Token()

	es.logger.Debug("Fetched character "+strconv.Itoa(int(claims.CharacterID)), "name", claims.CharacterName, "corp", CorporationID, "alliance", AllianceID)

	StoredSession.AllianceID = AllianceID
	StoredSession.CorpID = CorporationID
	StoredSession.CharID = strconv.Itoa(int(claims.CharacterID))
	StoredSession.Name = claims.CharacterName
	StoredSession.RefreshEVE = time.Now().Add(12 * time.Hour)
	StoredSession.Token = token

	es.logger.Debug("Stored character " + strconv.Itoa(int(claims.CharacterID)) + " to memory")

	if optionalCookie != "" {
		es.logger.Debug("ESI Fetch complete. Triggering database resync...")
		es.databaseAPI.SyncMemory(optionalCookie, true)
	}

	return nil

}

func (es *ESIService) VerifyUser(cookie string, doNotSync bool) *UserAuthDetails {
	if _, exists := preventDoS[cookie]; exists {
		es.logger.Warn("User has attempted to login with a blacklisted cookie", "cookie", cookie)
		return &UserAuthDetails{
			Allow: false,
		}
	}
	es.logger.Debug("Checking Logged in Sessions", "cookie", cookie)
	es.ActiveLoggedInSessions.Mutex.RLock()
	session := es.ActiveLoggedInSessions.Sessions[cookie]
	es.ActiveLoggedInSessions.Mutex.RUnlock()
	if session == nil {
		es.logger.Debug("Session is nil", "cookie", cookie)
		if doNotSync {
			es.logger.Debug("Blacklisting cookie", "cookie", cookie)
			preventDoS[cookie] = struct{}{}
			return &UserAuthDetails{
				Allow: false,
			}
		} else {
			es.logger.Debug("Attempting DB sync", "cookie", cookie)
			es.databaseAPI.SyncMemory(cookie, false)
			return es.VerifyUser(cookie, true)
		}

	}

	err := es.UpdateEVEInfo(session, false, cookie)

	if err != nil {
		es.logger.Error("Update Eve Info returned error - clearing stored session and denying", "cookie", cookie, "error", err)
		es.ActiveLoggedInSessions.Mutex.Lock()
		delete(es.ActiveLoggedInSessions.Sessions, cookie)
		es.ActiveLoggedInSessions.Mutex.Unlock()

		es.databaseAPI.Delete(cookie)

		return &UserAuthDetails{
			Allow: false,
		}
	}

	session.Mutex.RLock()
	DBUpdateTime := session.RefreshDB
	User := session.CharID
	UName := session.Name
	Role := session.Role
	session.Mutex.RUnlock()

	if time.Now().After(DBUpdateTime) {
		es.databaseAPI.SyncMemory(cookie, false)
		return es.VerifyUser(cookie, true)
	}

	final := &UserAuthDetails{
		Allow: false,
		User:  User,
		Uname: UName,
		Role:  Role,
	}

	session.Mutex.RLock()
	for _, uid := range es.config.Overrides.Super_Admin_IDs {
		if uid == session.CharID {
			final.Allow = true
		}
	}

	for _, cid := range es.config.Overrides.Corp_Allow {
		if cid == session.CorpID {
			final.Allow = true
		}
	}

	for _, aid := range es.config.Overrides.Alliance_Allow {
		if aid == session.AllianceID {
			final.Allow = true
		}
	}

	session.Mutex.RUnlock()

	return final
}

// TERNARY SUPPORT ?
func If[T any](cond bool, vtrue, vfalse T) T {
	if cond {
		return vtrue
	}
	return vfalse
}
