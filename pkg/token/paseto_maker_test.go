package token

import (
	"testing"
	"time"

	utils "github.com/demola234/defifundr/pkg/random"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestPasetoMaker(t *testing.T) {
	maker, err := NewTokenMaker(utils.RandomString(32))
	require.NoError(t, err)

	username := utils.RandomString(6)
	userID := uuid.New()
	duration := time.Minute
	issuedAt := time.Now()
	expiredAt := issuedAt.Add(duration)
	userType := "admin"
	tok, payload, err := maker.CreateToken(username, userID, duration, userType)
	require.NoError(t, err)

	require.NotEmpty(t, tok)
	require.NotEmpty(t, payload)

	require.Equal(t, username, payload.Email)
	require.WithinDuration(t, issuedAt, payload.IssuedAt, time.Second)
	require.WithinDuration(t, expiredAt, payload.ExpiredAt, time.Second)

	payload, err = maker.VerifyToken(tok)
	require.NoError(t, err)
	require.NotEmpty(t, payload)

	require.Equal(t, username, payload.Email)
	require.WithinDuration(t, issuedAt, payload.IssuedAt, time.Second)
	require.WithinDuration(t, expiredAt, payload.ExpiredAt, time.Second)
	require.NoError(t, payload.Valid())

}

func TestExpiredPasetoToken(t *testing.T) {
	maker, err := NewTokenMaker(utils.RandomString(32))
	require.NoError(t, err)
	require.NotEmpty(t, maker)

	userType := "user"
	tok, pasto_payload, err := maker.CreateToken(utils.RandomOwner(), uuid.New(), -time.Minute, userType)
	require.NoError(t, err)
	require.NotEmpty(t, tok)
	require.NotEmpty(t, pasto_payload)

	payload, err := maker.VerifyToken(tok)
	require.Error(t, err)

	require.Error(t, err)
	require.EqualError(t, err, ErrExpiredToken.Error())
	require.Empty(t, payload)
}

func TestInvalidToken(t *testing.T) {
	maker, err := NewTokenMaker(utils.RandomString(32))
	require.NoError(t, err)
	require.NotEmpty(t, maker)

	payload, err := maker.VerifyToken("invalid_token")
	require.Error(t, err)
	require.EqualError(t, err, ErrInvalidToken.Error())
	require.Empty(t, payload)
}
