package token

import (
	"time"

	"github.com/google/uuid"
)

type Maker interface {
	// CreateToken creates a new token for a specific username and duration
	CreateToken(email string, userID uuid.UUID, duration time.Duration, userType string) (string, *Payload, error)

	// VerifyToken checks if the token is valid or not
	VerifyToken(token string) (*Payload, error)
}
