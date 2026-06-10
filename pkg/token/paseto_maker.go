package token

import (
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/o1egl/paseto"
	"golang.org/x/crypto/chacha20poly1305"
)

type PasetoMaker struct {
	paseto       *paseto.V2
	symmetricKey []byte
}

var (
	ErrInvalidToken   = errors.New("token is invalid")
	ErrExpiredToken   = errors.New("token has expired")
	ErrInvalidKeySize = errors.New("invalid key size: must be exactly 32 bytes")
)

func NewTokenMaker(symmetricKey string) (Maker, error) {
	if len(symmetricKey) != chacha20poly1305.KeySize {
		return nil, ErrInvalidKeySize
	}

	maker := &PasetoMaker{
		paseto:       paseto.NewV2(),
		symmetricKey: []byte(symmetricKey),
	}

	return maker, nil
}

func (maker *PasetoMaker) CreateToken(email string, userID uuid.UUID, duration time.Duration, userType string) (string, *Payload, error) {
	payload, err := NewPayload(email, userID, duration, userType)
	if err != nil {
		return "", payload, err
	}

	tok, err := maker.paseto.Encrypt(maker.symmetricKey, payload, nil)
	if err != nil {
		return "", payload, err
	}

	return tok, payload, nil
}

func (maker *PasetoMaker) VerifyToken(tok string) (*Payload, error) {
	payload := &Payload{}
	err := maker.paseto.Decrypt(tok, maker.symmetricKey, payload, nil)

	if err != nil {
		return nil, ErrInvalidToken
	}

	err = payload.Valid()
	if err != nil {
		return nil, err
	}

	return payload, nil
}
