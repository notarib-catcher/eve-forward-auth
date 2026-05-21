package database

var queries = map[string]string{
	"InitSessions": `CREATE TABLE IF NOT EXISTS sessions (
		Cookie          TEXT        NOT NULL,
		CharacterID     TEXT        NOT NULL,
		CharacterName   TEXT        NOT NULL,
		CorporationID   TEXT        NOT NULL,
		AllianceID      TEXT        NOT NULL,
		AccessToken     TEXT        NOT NULL,
		RefreshToken	TEXT		NOT NULL,
		TokenExpiry     TIMESTAMTZ  NOT NULL,
		TokenType       TEXT        NOT NULL,
		Role			TEXT		NOT NULL,
		NextESISync     TIMESTAMPTZ NOT NULL,

		PRIMARY KEY (Cookie)
		);
		CREATE INDEX IF NOT EXISTS idx_sessions_characterid ON sessions (CharacterID);`,

	"initRoleUpdates": `CREATE TABLE IF NOT EXISTS pendingRoleUpdates (
		CharacterID     TEXT        NOT NULL,
		NewRole         TEXT        NOT NULL,

		PRIMARY KEY (CharacterID)
		);`,

	"fixRoles": `WITH pending AS (
			DELETE FROM pendingRoleUpdates
			WHERE CharacterID = $1
			AND EXISTS (SELECT 1 FROM sessions WHERE CharacterID = $1)
			RETURNING NewRole
		)
		UPDATE sessions
		SET Role = pending.NewRole
		FROM pending
		WHERE sessions.CharacterID = $1;`,

	"purgeByID": `DELETE FROM sessions
        WHERE CharacterID = $1`,

	"fetchFromDB": `SELECT CharacterID, CharacterName, CorporationID, AllianceID, AccessToken, RefreshToken, TokenExpiry, TokenType, Role, NextESISync
			FROM sessions
			WHERE Cookie = $1`,

	"fetchJustRoleFromDB": `SELECT Role
		FROM sessions
		WHERE Cookie = $1`,
}
