package identity_test

import (
	"testing"

	"github.com/caido/grafana-auth-proxy/pkg/identity"
	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
)

const (
	claimName = "Username"
	username  = "Sytten"
)

func TestTokenProvider(t *testing.T) {
	tokenProvider := identity.NewTokenProvider(claimName)
	claims := jwt.MapClaims{claimName: username}

	userId, err := tokenProvider.Identify(claims)

	assert.Nil(t, err)
	assert.Equal(t, userId, username)
}

func TestTokenProviderMissingClaim(t *testing.T) {
	tokenProvider := identity.NewTokenProvider(claimName)
	claims := jwt.MapClaims{}

	userId, err := tokenProvider.Identify(claims)

	assert.NotNil(t, err)
	assert.Empty(t, userId)
}

func TestTokenProviderEmptyClaim(t *testing.T) {
	tokenProvider := identity.NewTokenProvider(claimName)
	claims := jwt.MapClaims{claimName: ""}

	userId, err := tokenProvider.Identify(claims)

	assert.NotNil(t, err)
	assert.Empty(t, userId)
}

func TestTokenProviderInvalidClaim(t *testing.T) {
	tokenProvider := identity.NewTokenProvider(claimName)
	claims := jwt.MapClaims{claimName: []string{username}}

	userId, err := tokenProvider.Identify(claims)

	assert.NotNil(t, err)
	assert.Empty(t, userId)
}
