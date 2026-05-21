package database

import (
	"context"
	"errors"
	"eve-forward-auth/types"
	"sync"
	"time"

	log "github.com/charmbracelet/log"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/oauth2"
)

type DatabaseAPI struct {
	logger         *log.Logger
	ShutdownSignal context.Context
	CleanupTracker *sync.WaitGroup
	Sessions       *types.ActiveAuthenticatedSessions
	config         types.Config
	dbpool         *pgxpool.Pool
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

	logger.Info("Database Connected.")
	CleanupTracker.Go(func() {
		<-ShutdownSignal.Done()
		done := make(chan int, 1)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		logger.Info("Closing DB pool...")
		go func() {
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

	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = dbpool.Exec(ctx, queries["fixRoles"])
	if err != nil {
		logger.Fatal("Could not update roles", "error", err)
	}

	return &DatabaseAPI{
		logger:         logger,
		ShutdownSignal: ShutdownSignal,
		CleanupTracker: CleanupTracker,
		Sessions:       Sessions,
		config:         *Config,
		dbpool:         dbpool,
	}
}

func (d *DatabaseAPI) SyncMemory(cookie string, force bool) {
	// If not present in memory >> Populate all fields from DB
	// If present in memory >> Copy all fields except role to DB and save
	// Role is always synced from DB to Memory
	d.logger.Debug("Checking for existing session...")
	d.Sessions.Mutex.RLock()
	session := d.Sessions.Sessions[cookie]
	d.Sessions.Mutex.RUnlock()

	if session == nil {
		d.logger.Debug("Session is empty, fetching...")
		//Fetch from DB
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := d.dbpool.Exec(ctx, queries["fixRoles"])
		if err != nil {
			d.logger.Error("Could not update roles", "error", err)
			return
		}
		s := &storedSession{}
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err = d.dbpool.QueryRow(ctx, queries["fetchFromDB"], cookie).Scan(
			&s.CharacterID,
			&s.CharacterName,
			&s.CorporationID,
			&s.AllianceID,
			&s.AccessToken,
			&s.RefreshToken,
			&s.TokenExpiry,
			&s.TokenType,
			&s.Role,
			&s.NextESISync)
		if err != nil {
			d.logger.Error("Could not fetch session", "cookie", cookie, "error", err)
			return
		}

		d.logger.Debug("Fetched session!", "for", s.CharacterName, "cookie", cookie)

		token := oauth2.Token{
			Expiry:       s.TokenExpiry,
			AccessToken:  s.AccessToken,
			RefreshToken: s.RefreshToken,
			TokenType:    s.TokenType,
		}

		session = &types.ActiveAuthenticatedSession{
			Mutex:      sync.RWMutex{},
			Token:      &token,
			Name:       s.CharacterName,
			CharID:     s.CharacterID,
			CorpID:     s.CorporationID,
			AllianceID: s.AllianceID,
			RefreshEVE: s.NextESISync,
			Role:       s.Role,
			RefreshDB:  time.Now().Add(5 * time.Minute),
		}

		d.Sessions.Mutex.Lock()
		defer d.Sessions.Mutex.Unlock()
		existing_session := d.Sessions.Sessions[cookie]

		if existing_session != nil {
			//another thread has already updated it
			d.logger.Debug("Session has been updated b/w first and second check. Performing no update")
			return
		}

		d.logger.Debug("Adding session to in-memory pool", "cookie", cookie)
		d.Sessions.Sessions[cookie] = session
		return

	} else {
		d.logger.Debug("Session already present in memory")
		session.Mutex.Lock()
		defer session.Mutex.Unlock()

		if !force && session.RefreshDB.After(time.Now()) {
			d.logger.Debug("Refresh not required")
			return
		}
		d.logger.Debug("Refreshing")

		session.RefreshDB = time.Now().Add(5 * time.Minute)
		d.logger.Debug("Running fixroles")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := d.dbpool.Exec(ctx, queries["fixRoles"])
		if err != nil {
			d.logger.Error("Could not update roles", "error", err)
			return
		}
		d.logger.Debug("Fetching just role from DB")
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var DBRole string
		err = d.dbpool.QueryRow(ctx, queries["fetchJustRoleFromDB"], cookie).Scan(
			&DBRole)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				d.logger.Debug("No entry Exists, doing full save to DB")

				//Full DB update required - no entry exists
				//This is only reached occasionally, when a new entry is first made. As such, having a bit of a longer block is acceptable
				s := &storedSession{
					CharacterID:   session.CharID,
					CorporationID: session.CorpID,
					AllianceID:    session.AllianceID,
					TokenExpiry:   session.Token.Expiry,
					TokenType:     session.Token.TokenType,
					AccessToken:   session.Token.AccessToken,
					RefreshToken:  session.Token.RefreshToken,
					NextESISync:   session.RefreshEVE,
					CharacterName: session.Name,
					Role:          d.config.Database.Default_Role,
				}

				ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()

				_, err = d.dbpool.Exec(ctx, queries["insertOrUpdateAll"],
					cookie,
					s.CharacterID,
					s.CharacterName,
					s.CorporationID,
					s.AllianceID,
					s.AccessToken,
					s.RefreshToken,
					s.TokenExpiry,
					s.TokenType,
					s.Role,
					s.NextESISync)

				if err != nil {
					d.logger.Error("Could not insert new entry", "cookie", cookie, "error", err)
					return
				}

				ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()

				_, err = d.dbpool.Exec(ctx, queries["syncSimilarEntries"], cookie)

				if err != nil {
					d.logger.Error("Entry sync with similar entries - failed", "cookie", cookie, "error", err)
					return
				}

				d.logger.Debug("Syncing roles with fixroles on new DB entry")
				ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_, err := d.dbpool.Exec(ctx, queries["fixRoles"])
				if err != nil {
					d.logger.Error("Could not update roles", "error", err)
					return
				}
				//AAaand sync it again to memory
				d.logger.Debug("Fetching role to memory post sync on new enty")

				ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				var DBRole string
				err = d.dbpool.QueryRow(ctx, queries["fetchJustRoleFromDB"], cookie).Scan(
					&DBRole)

				if err != nil {
					d.logger.Error("Could not fetch roles", "cookie", cookie, "error", err)
					return
				}

				session.Role = DBRole

				return
			} else {
				d.logger.Error("Fetching DB entry (role check) fail", "error", err)
				return
			}
		}

		d.logger.Debug("Entry Present. Syncing Role FROM database and all other values TO database")

		//Sync just role FROM DB and sync rest TO DB
		session.Role = DBRole

		s := &storedSession{
			CharacterID:   session.CharID,
			CorporationID: session.CorpID,
			AllianceID:    session.AllianceID,
			TokenExpiry:   session.Token.Expiry,
			TokenType:     session.Token.TokenType,
			AccessToken:   session.Token.AccessToken,
			RefreshToken:  session.Token.RefreshToken,
			NextESISync:   session.RefreshEVE,
			CharacterName: session.Name,
		}

		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_, err = d.dbpool.Exec(ctx, queries["insertOrUpdateAllExceptRole"],
			cookie,
			s.CharacterID,
			s.CharacterName,
			s.CorporationID,
			s.AllianceID,
			s.AccessToken,
			s.RefreshToken,
			s.TokenExpiry,
			s.TokenType,
			s.NextESISync)

		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_, err = d.dbpool.Exec(ctx, queries["syncSimilarEntries"], cookie)

		if err != nil {
			d.logger.Error("Entry sync with similar entries after update - failed", "cookie", cookie, "error", err)
			return
		}

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
