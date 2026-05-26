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
		NextESISync     TIMESTAMPTZ NOT NULL,

		PRIMARY KEY (Cookie)
		);
		CREATE INDEX IF NOT EXISTS idx_sessions_characterid ON sessions (CharacterID);`,

	"initRoleUpdates": `CREATE TABLE IF NOT EXISTS roleOverrides (
		CharacterID     VARCHAR        NOT NULL,
		Role         	VARCHAR        NOT NULL,

		PRIMARY KEY (CharacterID)
		);`,

	"fixRoles": `WITH pending AS (
			DELETE FROM roleOverrides
			WHERE EXISTS (SELECT 1 FROM sessions WHERE sessions.CharacterID = roleOverrides.CharacterID)
			RETURNING CharacterID, Role
		)
		UPDATE sessions
		SET Role = pending.Role
		FROM pending
		WHERE sessions.CharacterID = pending.CharacterID;`,

	"purgeByID": `DELETE FROM sessions
        WHERE CharacterID = $1`,

	"deleteByCookie": `DELETE FROM sessions
        WHERE Cookie = $1`,
}
