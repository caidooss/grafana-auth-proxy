package identity

import (
	"errors"
	"fmt"

	"github.com/dgrijalva/jwt-go"
)

type Provider interface {
	Identify(claims jwt.MapClaims) (string, error)
}

type tokenProvider struct {
	claimName string
}

func NewTokenProvider(claimName string) *tokenProvider {
	return &tokenProvider{claimName}
}

func (tp *tokenProvider) Identify(claims jwt.MapClaims) (string, error) {
	// Get claim
	claim := claims[tp.claimName]
	if claim == nil {
		return "", errors.New(fmt.Sprintf("missing claim %s", tp.claimName))
	}

	// Cast claim
	claimString, ok := claim.(string)
	if !ok || claimString == "" {
		return "", errors.New(fmt.Sprintf("invalid value for claim %s", tp.claimName))
	}

	return claimString, nil
}
