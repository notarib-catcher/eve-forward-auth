package database

import "time"

type storedSession struct {
	CharacterID   string
	CharacterName string
	CorporationID string
	AllianceID    string
	AccessToken   string
	RefreshToken  string
	TokenExpiry   time.Time
	TokenType     string
	Role          string
	NextESISync   time.Time
}
