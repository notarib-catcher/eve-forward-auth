package database

var queries = map[string]string{
	"InitSessions": `CREATE TABLE IF NOT EXISTS sessions (
		Cookie          VARCHAR        NOT NULL,
		CharacterID     VARCHAR        NOT NULL,
		CharacterName   VARCHAR        NOT NULL,
		CorporationID   VARCHAR        NOT NULL,
		AllianceID      VARCHAR        NOT NULL,
		AccessToken     VARCHAR        NOT NULL,
		RefreshToken	VARCHAR		NOT NULL,
		TokenExpiry     TIMESTAMPTZ NOT NULL,
		TokenType       VARCHAR        NOT NULL,
		Role			VARCHAR		NOT NULL,
		NextESISync     TIMESTAMPTZ NOT NULL,

		PRIMARY KEY (Cookie)
		);
		CREATE INDEX IF NOT EXISTS idx_sessions_characterid ON sessions (CharacterID);`,

	"initRoleUpdates": `CREATE TABLE IF NOT EXISTS pendingRoleUpdates (
		CharacterID     VARCHAR        NOT NULL,
		NewRole         VARCHAR        NOT NULL,

		PRIMARY KEY (CharacterID)
		);`,

	"fixRoles": `WITH pending AS (
			DELETE FROM pendingRoleUpdates
			WHERE EXISTS (SELECT 1 FROM sessions WHERE sessions.CharacterID = pendingRoleUpdates.CharacterID)
			RETURNING CharacterID, NewRole
		)
		UPDATE sessions
		SET Role = pending.NewRole
		FROM pending
		WHERE sessions.CharacterID = pending.CharacterID;`,

	"purgeByID": `DELETE FROM sessions
        WHERE CharacterID = $1`,

	"deleteByCookie": `DELETE FROM sessions
        WHERE Cookie = $1`,

	"fetchFromDB": `SELECT CharacterID, CharacterName, CorporationID, AllianceID, AccessToken, RefreshToken, TokenExpiry, TokenType, Role, NextESISync
			FROM sessions
			WHERE Cookie = $1`,

	"fetchJustRoleFromDB": `SELECT Role::text
		FROM sessions
		WHERE Cookie = $1`,

	"insertOrUpdateAll": `INSERT INTO sessions (Cookie, CharacterID, CharacterName, CorporationID, AllianceID, AccessToken, RefreshToken, TokenExpiry, TokenType, Role, NextESISync)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (Cookie) DO UPDATE
		SET CharacterName = $3, CorporationID = $4, AllianceID = $5, AccessToken = $6, RefreshToken = $7, TokenExpiry = $8, TokenType = $9, Role = $10, NextESISync = $11;
	`,

	"insertOrUpdateAllExceptRole": `UPDATE sessions
		SET CharacterName = $3, CorporationID = $4, AllianceID = $5, AccessToken = $6, RefreshToken = $7, TokenExpiry = $8, TokenType = $9, NextESISync = $10;
		WHERE CharacterID = $2 AND Cookie != $1;
	`,

	"syncSimilarEntries": `UPDATE sessions s
		SET
			CharacterName = src.CharacterName,
			CorporationID = src.CorporationID,
			AllianceID    = src.AllianceID,
			AccessToken   = src.AccessToken,
			RefreshToken  = src.RefreshToken,
			TokenExpiry   = src.TokenExpiry,
			TokenType     = src.TokenType,
			Role          = src.Role,
			NextESISync   = src.NextESISync
		FROM sessions src
		WHERE src.Cookie = $1
		AND s.CharacterID = src.CharacterID
		AND s.Cookie != src.Cookie;`,
}
