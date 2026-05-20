package esiservice

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
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

func NewESIService(logger *log.Logger, HostedAt string, Redirect_URL string, MemcachedAddresses []string, Config types.Config) *ESIService {

	nonCachingClient := &http.DefaultClient
	auth := goesi.NewSSOAuthenticatorV2(*nonCachingClient, Config.App_ID, Config.App_Secret, Redirect_URL, scopes)

	return &ESIService{
		logger:           logger,
		SSOAuthenticator: auth,
		ActiveAuthSessions: &AuthSessions{
			sessions: make(map[string]*AuthSession),
			mutex:    sync.Mutex{},
		},
		HostedAt: HostedAt,
		ActiveLoggedInSessions: &ActiveAuthenticatedSessions{
			sessions: make(map[string]*ActiveAuthenticatedSession),
			mutex:    sync.RWMutex{},
		},
		config: Config,
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

	NewSession := &ActiveAuthenticatedSession{
		token: token,
		mutex: sync.RWMutex{},
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "evefa_session_token",
		Domain:  es.config.Server.Domain,
		Value:   SessionCookie,
		Expires: time.Now().Add(180 * 24 * time.Hour), // 6 months
		Path:    "/",
	})

	//TODO: store this cookie in database

	err = es.UpdateEVEInfo(NewSession, true)
	if err != nil {
		es.logger.Error("Error while updating info from ESI", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Error fetching info from ESI"))

		if err.Error() == "Token Validation Error" {
			es.logger.Debug("Token Invalid")
		}
		return
	}

	es.ActiveLoggedInSessions.mutex.Lock()
	es.ActiveLoggedInSessions.sessions[SessionCookie] = NewSession
	es.ActiveLoggedInSessions.mutex.Unlock()

	http.Redirect(w, r, "http"+(If(es.config.Server.Is_Secure, "s", ""))+"://"+es.config.Server.Domain+"/"+es.config.Server.Prefix+"/success?redirect="+redirect, 200)
}

func (es *ESIService) UpdateEVEInfo(StoredSession *ActiveAuthenticatedSession, force bool) error {

	StoredSession.mutex.Lock()
	defer StoredSession.mutex.Unlock()
	if !force {
		if time.Now().Before(StoredSession.RefreshEVE) {
			return nil
		}
	}

	StoredToken := *StoredSession.token
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

	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return err
	}

	AllianceID := strconv.Itoa(result["alliance_id"].(int))
	CorporationID := strconv.Itoa(result["corporation_id"].(int))
	token, err := tokenSrc.Token()

	StoredSession.mutex.Lock()
	StoredSession.AllianceID = AllianceID
	StoredSession.CorpID = CorporationID
	StoredSession.CharID = strconv.Itoa(int(claims.CharacterID))
	StoredSession.Name = claims.CharacterName
	StoredSession.RefreshEVE = time.Now().Add(12 * time.Hour)
	StoredSession.token = token
	StoredSession.mutex.Unlock()

	//update DB here

	return nil

}

func (es *ESIService) VerifyUser(cookie string) *UserAuthDetails {
	es.ActiveLoggedInSessions.mutex.RLock()
	session := es.ActiveLoggedInSessions.sessions[cookie]
	es.ActiveLoggedInSessions.mutex.RUnlock()
	if session == nil {
		return &UserAuthDetails{
			Allow: false,
		}
	}

	err := es.UpdateEVEInfo(session, false)

	if err != nil {
		es.logger.Error("Update Eve Info returned error - clearing stored session and denying", "cookie", cookie, "error", err)
		es.ActiveLoggedInSessions.mutex.Lock()
		delete(es.ActiveLoggedInSessions.sessions, cookie)
		es.ActiveLoggedInSessions.mutex.Unlock()

		//TODO: Delete this entry from DB as well

		return &UserAuthDetails{
			Allow: false,
		}
	}

	session.mutex.RLock()
	DBUpdateTime := session.RefreshDB
	User := session.CharID
	UName := session.Name
	Role := session.Role
	session.mutex.RUnlock()

	if time.Now().After(DBUpdateTime) {
		// updateFromDB(cookie)
		return es.VerifyUser(cookie)
	}

	final := &UserAuthDetails{
		Allow: false,
		User:  User,
		Uname: UName,
		Role:  Role,
	}

	session.mutex.RLock()
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

	session.mutex.RUnlock()

	return final
}

// TERNARY SUPPORT ?
func If[T any](cond bool, vtrue, vfalse T) T {
	if cond {
		return vtrue
	}
	return vfalse
}
