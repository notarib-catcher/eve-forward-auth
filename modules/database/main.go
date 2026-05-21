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

func NewDB(logger *log.Logger, ShutdownSignal context.Context, CleanupTracker *sync.WaitGroup, Sessions *types.ActiveAuthenticatedSessions, Config *types.Config) *DatabaseAPI {
	dbpool, err := pgxpool.New(context.Background(), Config.Database.Postgres_Connection_String)
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
	d.Sessions.Mutex.RLock()
	session := d.Sessions.Sessions[cookie]
	d.Sessions.Mutex.RUnlock()

	if session == nil {
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
			d.logger.Error("Could not fetch session", "cookie", cookie, "error", err)
			return
		}

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
			RefreshDB:  time.Now().Add(time.Minute * 10),
		}

		d.Sessions.Mutex.Lock()
		defer session.Mutex.Unlock()
		session := d.Sessions.Sessions[cookie]

		if session != nil {
			//another thread has already updated it
			return
		}

		d.Sessions.Sessions[cookie] = session
		return

	} else {
		//Session present already. Update DB from memory
		session.Mutex.Lock()
		defer session.Mutex.Unlock()
		if !force && session.RefreshDB.After(time.Now()) {
			return
		}
		session.RefreshDB = time.Now().Add(5 * time.Minute)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := d.dbpool.Exec(ctx, queries["fixRoles"])
		if err != nil {
			d.logger.Error("Could not update roles", "error", err)
			return
		}

		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var DBRole string
		err = d.dbpool.QueryRow(ctx, queries["fetchJustRoleFromDB"], cookie).Scan(
			DBRole)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				//Full DB update required - no entry exists
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

				return
			} else {
				d.logger.Error("Fetching DB entry (role check) fail", "error", err)
				return
			}
		}

		//Sync just role FROM DB and sync rest TO DB

	}
}

func (d *DatabaseAPI) Delete(cookie string) {
	// Delete DB entry
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
