package database

import (
	"context"
	"errors"
	"eve-forward-auth/types"
	"sync"
	"time"

	log "github.com/charmbracelet/log"
	"github.com/go-co-op/gocron/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/oauth2"
)

type DatabaseAPI struct {
	logger           *log.Logger
	ShutdownSignal   context.Context
	CleanupTracker   *sync.WaitGroup
	Sessions         *types.ActiveAuthenticatedSessions
	config           *types.Config
	dbpool           *pgxpool.Pool
	charIDSessionMap map[string]*storedCharIDSessionRelation
	charIDMapMutex   *sync.RWMutex
}

// TODO: Simultaneously update other entries with same character ID with new values
// when existing data is updated.
// So that all entries with that character ID are synced up interms of tokens, etc.
// This would let people log in from different places at one time like phone + pc
// this is TODO on all places where data is inserted or updated in DB.

func NewDB(logger *log.Logger, ShutdownSignal context.Context, CleanupTracker *sync.WaitGroup, Sessions *types.ActiveAuthenticatedSessions, Config *types.Config) *DatabaseAPI {

	pgconfig, err := pgxpool.ParseConfig(Config.Database.Postgres_Connection_String)
	if err != nil {
		logger.Fatal("Could not parse postgres connection string", "error", err)
	}
	dbpool, err := pgxpool.NewWithConfig(context.Background(), pgconfig)
	if err != nil {
		logger.Fatal("Could not initialize database connection. Exiting.")
		ShutdownSignal.Done()
	}

	s, err := gocron.NewScheduler()
	if err != nil {
		logger.Fatal("Could not initialise CRON scheduler", "error", err)
	}

	defer s.Start()

	logger.Info("Database Connected.")
	CleanupTracker.Go(func() {
		<-ShutdownSignal.Done()
		done := make(chan int, 1)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		go func() {
			logger.Info("Closing running jobs...")
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
			defer cancel()
			s.ShutdownWithContext(ctx)
			logger.Info("Closing DB pool...")
			dbpool.Close()
			done <- 1
		}()

		select {
		case <-done:
			logger.Info("All connections closed")
		case <-ctx.Done():
			logger.Info("Database pool Close() has timed out.")

		}

	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = dbpool.Exec(ctx, queries["InitSessions"])
	if err != nil {
		logger.Fatal("Could not init session table", "error", err)
	}

	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = dbpool.Exec(ctx, queries["initRoleUpdates"])
	if err != nil {
		logger.Fatal("Could not init role update table", "error", err)
	}

	return &DatabaseAPI{
		logger:           logger,
		ShutdownSignal:   ShutdownSignal,
		CleanupTracker:   CleanupTracker,
		Sessions:         Sessions,
		config:           Config,
		dbpool:           dbpool,
		charIDSessionMap: make(map[string]*storedCharIDSessionRelation),
		charIDMapMutex:   &sync.RWMutex{},
	}
}

func (d *DatabaseAPI) Commit(cookie string) {
	d.Sessions.Mutex.RLock()
	session := d.Sessions.Sessions[cookie]
	d.Sessions.Mutex.RUnlock()

	d.logger.Debug("(Commit) Processing cookie", "cookie", cookie)

	if session == nil {
		d.logger.Error("(Commit) Session is nil", "cookie", cookie)
		return
	}

	session.Mutex.RLock()
	toStore := &storedSession{
		CharacterID:   session.CharID,
		CharacterName: session.Name,
		CorporationID: session.CorpID,
		AllianceID:    session.AllianceID,
		TokenExpiry:   session.Token.Expiry,
		TokenType:     session.Token.TokenType,
		AccessToken:   session.Token.AccessToken,
		RefreshToken:  session.Token.RefreshToken,
		NextESISync:   session.RefreshEVE,
	}
	session.Mutex.RUnlock()

	d.logger.Debug("(Commit) Got stored char", "name", toStore.CharacterName, "cookie", cookie)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tx, err := d.dbpool.Begin(ctx)
	if err != nil {
		d.logger.Error("(Commit) Could not begin transaction", "cookie", cookie, "error", err)
		return
	}
	defer tx.Rollback(ctx)

	d.logger.Debug("(Commit) Inserting DB", "cookie", cookie)
	_, err = tx.Exec(ctx, `
		INSERT INTO sessions (Cookie, CharacterID, CharacterName, CorporationID, AllianceID, AccessToken, RefreshToken, TokenExpiry, TokenType, NextESISync)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (Cookie) DO UPDATE
		SET CharacterName = $3, CorporationID = $4, AllianceID = $5, AccessToken = $6, RefreshToken = $7, TokenExpiry = $8, TokenType = $9, NextESISync = $10
	`, cookie, toStore.CharacterID, toStore.CharacterName, toStore.CorporationID, toStore.AllianceID, toStore.AccessToken, toStore.RefreshToken, toStore.TokenExpiry, toStore.TokenType, toStore.NextESISync)
	if err != nil {
		d.logger.Error("(Commit) Could not upsert session", "cookie", cookie, "error", err)
		return
	}

	d.logger.Debug("(Commit) Sync DB siblings", "name", toStore.CharacterName, "id", toStore.CharacterID)
	_, err = tx.Exec(ctx, `
		UPDATE sessions
		SET CharacterName = $1, CorporationID = $2, AllianceID = $3, AccessToken = $4, RefreshToken = $5, TokenExpiry = $6, TokenType = $7, NextESISync = $8
		WHERE CharacterID = $9 AND Cookie != $10
	`, toStore.CharacterName, toStore.CorporationID, toStore.AllianceID, toStore.AccessToken, toStore.RefreshToken, toStore.TokenExpiry, toStore.TokenType, toStore.NextESISync, toStore.CharacterID, cookie)
	if err != nil {
		d.logger.Error("(Commit) Could not sync siblings", "cookie", cookie, "error", err)
		return
	}

	d.logger.Debug("(Commit) Committing", "name", toStore.CharacterName, "cookie", cookie)
	if err = tx.Commit(ctx); err != nil {
		d.logger.Error("(Commit) Could not commit transaction", "cookie", cookie, "error", err)
		return
	}

	newSessionTracker := &storedCharIDSessionRelation{
		Mutex:    &sync.RWMutex{},
		sessions: []string{cookie},
	}

	d.charIDMapMutex.RLock()
	sessionTracker := d.charIDSessionMap[toStore.CharacterID]
	d.charIDMapMutex.RUnlock()

	if sessionTracker == nil {
		d.charIDMapMutex.Lock()

		//debounce
		if d.charIDSessionMap[toStore.CharacterID] == nil {
			d.charIDSessionMap[toStore.CharacterID] = newSessionTracker
		}

		//commit
		d.charIDMapMutex.Unlock()
		return
	}

	//update existing
	sessionTracker.Mutex.Lock()
	sessionTracker.sessions = append(sessionTracker.sessions, cookie)
	sessionTracker.Mutex.Unlock()

}

func (d *DatabaseAPI) Fetch(cookie string, force bool) {

	needFullFetch := false

	d.Sessions.Mutex.RLock()
	session := d.Sessions.Sessions[cookie]
	d.Sessions.Mutex.RUnlock()

	if session == nil {
		needFullFetch = true
	}

	if !needFullFetch {
		session.Mutex.RLock()
		charID := session.CharID
		corpID := session.CorpID
		allianceID := session.AllianceID
		refreshTime := session.RefreshDB
		session.Mutex.RUnlock()

		//Not forced, check if refresh needed
		if !force && !time.Now().After(refreshTime) {
			d.logger.Debug("(Fetch) Skipping partial DB fetch")
			return
		}
		var dbrole string
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := d.dbpool.QueryRow(ctx, "SELECT Role from roleOverrides where CharacterID = $1", charID).Scan(&dbrole)
		if errors.Is(err, pgx.ErrNoRows) {
			//Session exists and no role override is set
			d.logger.Debug("Assigning Default role based on perm check")
			_, permrole := CheckPermissionsAndGetMinimumRole(d.config, charID, corpID, allianceID)

			session.Mutex.Lock()
			session.Role = permrole
			session.RefreshDB = time.Now().Add(5 * time.Minute)
			session.Mutex.Unlock()
			d.UpdateSiblingSessionRoles(charID, permrole, cookie)

		} else {
			//There is a role override

			session.Mutex.Lock()
			session.Role = dbrole
			session.RefreshDB = time.Now().Add(5 * time.Minute)
			session.Mutex.Unlock()
			d.UpdateSiblingSessionRoles(charID, dbrole, cookie)

		}

		return
	}

	// do full udpate

	s := &storedSession{}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := d.dbpool.QueryRow(ctx, `SELECT s.CharacterID, s.CharacterName, s.CorporationID, s.AllianceID, s.AccessToken, s.RefreshToken, s.TokenExpiry, s.TokenType, s.NextESISync, COALESCE(r.Role, '[ROLE_UNSET]') as Role
        FROM sessions s
        LEFT JOIN roleOverrides r ON s.CharacterID = r.CharacterID
        WHERE s.Cookie = $1
    `, cookie).Scan(&s.CharacterID, &s.CharacterName, &s.CorporationID, &s.AllianceID, &s.AccessToken, &s.RefreshToken, &s.TokenExpiry, &s.TokenType, &s.NextESISync, &s.Role)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			d.logger.Debug("No session found in DB", "cookie", cookie)
			return
		} else {
			d.logger.Error("An error occured while fetching from db", "error", err, "cookie", cookie)
			return
		}
	}

	if s.Role == "[ROLE_UNSET]" {
		_, s.Role = CheckPermissionsAndGetMinimumRole(d.config, s.CharacterID, s.CorporationID, s.AllianceID)
	}
	newSession := &types.ActiveAuthenticatedSession{
		CharID:     s.CharacterID,
		Name:       s.CharacterName,
		CorpID:     s.CorporationID,
		AllianceID: s.AllianceID,
		Token: &oauth2.Token{
			TokenType:    s.TokenType,
			Expiry:       s.TokenExpiry,
			AccessToken:  s.AccessToken,
			RefreshToken: s.RefreshToken,
		},
		Role:       s.Role,
		RefreshDB:  time.Now().Add(5 * time.Minute),
		RefreshEVE: s.NextESISync,
		Mutex:      sync.RWMutex{},
	}

	d.Sessions.Mutex.Lock()

	//debounce
	if d.Sessions.Sessions[cookie] != nil {
		d.Sessions.Mutex.Unlock()
		return
	}

	d.Sessions.Sessions[cookie] = newSession
	d.Sessions.Mutex.Unlock()

	d.charIDMapMutex.RLock()

	var sessionTracker *storedCharIDSessionRelation

	if _, exists := d.charIDSessionMap[s.CharacterID]; exists {
		sessionTracker = d.charIDSessionMap[s.CharacterID]
		d.charIDMapMutex.RUnlock()
		sessionTracker.Mutex.Lock()
		sessionTracker.sessions = append(sessionTracker.sessions, cookie)
		sessionTracker.Mutex.Unlock()
		return
	}
	d.charIDMapMutex.RUnlock()

	//add new sessionTracker again
	d.charIDMapMutex.Lock()

	//debounce check
	check := d.charIDSessionMap[s.CharacterID]
	if check != nil {
		d.charIDMapMutex.Unlock()
		return
	}

	sessionTracker = &storedCharIDSessionRelation{
		sessions: []string{cookie},
		Mutex:    &sync.RWMutex{},
	}

	d.charIDSessionMap[s.CharacterID] = sessionTracker
	d.charIDMapMutex.Unlock()

	d.UpdateSiblingSessionRoles(s.CharacterID, s.Role, cookie)

	return

}

func (d *DatabaseAPI) UpdateSiblingSessionRoles(charID string, role string, exclude string) {
	d.charIDMapMutex.RLock()
	cookieTracker := d.charIDSessionMap[charID]
	d.charIDMapMutex.RUnlock()

	if cookieTracker == nil {
		d.logger.Error("(UpdateSibling) Sessionlist not found")
		return
	}

	cookieTracker.Mutex.RLock()
	sessionList := make([]string, len(cookieTracker.sessions))

	//Make a copy - this way we have no instance in time where we have 2 mutexes held by one function
	copy(sessionList, cookieTracker.sessions)
	cookieTracker.Mutex.RUnlock()

	if len(sessionList) <= 1 {
		d.logger.Debug("(UpdateSibling) No siblings to update", "charID", charID, "exclude", exclude, "len", len(sessionList))
		return
	}

	var sessionsToUpdate []*types.ActiveAuthenticatedSession

	d.Sessions.Mutex.RLock()

	for _, cookie := range sessionList {
		if cookie == exclude {
			continue
		}
		session := d.Sessions.Sessions[cookie]
		if session != nil {
			sessionsToUpdate = append(sessionsToUpdate, session)
		}
	}
	d.Sessions.Mutex.RUnlock()

	for _, session := range sessionsToUpdate {
		session.Mutex.Lock()
		session.Role = role
		session.Mutex.Unlock()
	}

}

func (d *DatabaseAPI) Delete(cookie string) {
	//Checking with RLock as a DoS prevention measure
	d.Sessions.Mutex.RLock()
	session := d.Sessions.Sessions[cookie]
	d.Sessions.Mutex.RUnlock()
	if session == nil {
		return
	}

	d.Sessions.Mutex.Lock()
	defer d.Sessions.Mutex.Unlock()
	session = d.Sessions.Sessions[cookie]
	if session == nil {
		return
	}

	delete(d.Sessions.Sessions, cookie)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := d.dbpool.Exec(ctx, queries["deleteByCookie"], cookie)
	if err != nil {
		d.logger.Error("Could not purge", "error", err)
		return
	}

}

func (d *DatabaseAPI) Purge(cookie string) {
	d.Sessions.Mutex.RLock()
	session := d.Sessions.Sessions[cookie]
	d.Sessions.Mutex.RUnlock()
	if session == nil {
		return
	}

	session.Mutex.RLock()
	toDeleteChar := session.CharID
	session.Mutex.RUnlock()

	//We do the check again. The first time, we do an RLock so as to not block the other reads incase it is a DoS/Spam
	d.Sessions.Mutex.Lock()
	session = d.Sessions.Sessions[cookie]
	if session == nil {
		//Doesnt exist anymore - another thread probably deleted it bc of a duplicate request a few ms apart
		d.Sessions.Mutex.Unlock()
		return
	}

	//Make a full copy of the current map, then release the lock
	sessions := make(map[string]*types.ActiveAuthenticatedSession, len(d.Sessions.Sessions))
	for k, v := range d.Sessions.Sessions {
		sessions[k] = v
	}
	d.Sessions.Mutex.Unlock()
	var toDelete []string
	for k, v := range sessions {
		if v.CharID == toDeleteChar {
			toDelete = append(toDelete, k)
		}
	}

	//Finally, delete.
	d.Sessions.Mutex.Lock()
	for _, v := range toDelete {
		delete(d.Sessions.Sessions, v)
	}
	d.Sessions.Mutex.Unlock()

	//NOW WE PURGE FROM DB
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := d.dbpool.Exec(ctx, queries["purgeFromDB"], toDeleteChar)
	if err != nil {
		d.logger.Error("Could not purge", "error", err)
		return
	}

}

func (d *DatabaseAPI) GetSessionsForChar(charID string) []string {
	d.charIDMapMutex.RLock()
	sessionTracker := d.charIDSessionMap[charID]
	d.charIDMapMutex.RUnlock()

	if sessionTracker == nil {
		d.logger.Warn("(GetSessionForChar) No session tracker found", "charID", charID)
		return []string{}
	}

	sessionTracker.Mutex.RLock()
	sessions := make([]string, len(sessionTracker.sessions))
	copy(sessions, sessionTracker.sessions)
	sessionTracker.Mutex.RUnlock()

	return sessions
}

func (d *DatabaseAPI) PutSessionForChar(charID string, cookie string) {
	d.charIDMapMutex.RLock()
	sessionTracker := d.charIDSessionMap[charID]
	d.charIDMapMutex.RUnlock()

	if sessionTracker == nil {
		d.logger.Error("(PutSessionForChar) No tracker for charID. Was it never initialized via a DB fetch or insert first?", "charID", charID)
		return
	}

	sessionTracker.Mutex.Lock()
	sessionTracker.sessions = append(sessionTracker.sessions, cookie)
	sessionTracker.Mutex.Unlock()
}
