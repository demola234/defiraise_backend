package token

import (
	"time"

	"github.com/google/uuid"
)

type Payload struct {
	Email     string    `json:"email"`
	UserID    uuid.UUID `json:"user_id"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiredAt time.Time `json:"expired_at"`
	UserType  string    `json:"user_type"`
}

func NewPayload(email string, userID uuid.UUID, duration time.Duration, userType string) (*Payload, error) {

	payload := &Payload{
		Email:     email,
		UserID:    userID,
		IssuedAt:  time.Now(),
		ExpiredAt: time.Now().Add(duration),
		UserType: userType,
	}

	return payload, nil
}

func (payload *Payload) Valid() error {
	if time.Now().After(payload.ExpiredAt) {
		return ErrExpiredToken
	}

	return nil
}
