package validation_test

import (
	"crypto/rsa"
	"testing"
	"time"

	"github.com/caido/grafana-auth-proxy/pkg/authtest"
	"github.com/caido/grafana-auth-proxy/pkg/validation"
	"github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/stretchr/testify/assert"
)

func setupValidationTest() (*rsa.PrivateKey, *rsa.PublicKey, jwt.MapClaims, *rsa.PrivateKey) {
	privateKey := authtest.LoadPrivateKey()
	publicKey := authtest.LoadPublicKey()
	attackerKey := authtest.LoadAttackerPrivateKey()
	claims := authtest.GetDefaultClaims()
	return privateKey, publicKey, claims, attackerKey
}

func getTokenValidator(publicKey *rsa.PublicKey) *validation.TokenValidator {
	rawKeys := authtest.GetRawRS256Jwk(publicKey)
	keys, _ := jwk.ParseString(rawKeys)
	return validation.NewTokenValidator(
		keys,
		[]string{authtest.Algorithm},
		authtest.Audience,
		authtest.Issuer,
	)
}

func TestValidToken(t *testing.T) {
	privateKey, publicKey, claims, _ := setupValidationTest()
	tokenValidator := getTokenValidator(publicKey)

	rawToken := authtest.CreateTokenString(claims, privateKey)
	token, err := tokenValidator.Validate(rawToken)

	assert.Nil(t, err)
	assert.NotNil(t, token)
}

func TestBadIssuerToken(t *testing.T) {
	privateKey, publicKey, claims, _ := setupValidationTest()
	tokenValidator := getTokenValidator(publicKey)

	claims["iss"] = "bad_issuer"
	rawToken := authtest.CreateTokenString(claims, privateKey)
	_, err := tokenValidator.Validate(rawToken)

	if assert.NotNil(t, err) {
		assert.Equal(t, validation.ErrorIssuer, err.(*validation.Error).Code)
	}
}

func TestBadAudienceToken(t *testing.T) {
	privateKey, publicKey, claims, _ := setupValidationTest()
	tokenValidator := getTokenValidator(publicKey)

	claims["aud"] = "bad_audience"
	rawToken := authtest.CreateTokenString(claims, privateKey)
	_, err := tokenValidator.Validate(rawToken)

	if assert.NotNil(t, err) {
		assert.Equal(t, validation.ErrorAudience, err.(*validation.Error).Code)
	}
}

func TestExpiredToken(t *testing.T) {
	privateKey, publicKey, claims, _ := setupValidationTest()
	tokenValidator := getTokenValidator(publicKey)

	claims["iat"] = time.Now().Unix() - 300
	claims["exp"] = time.Now().Unix() - 30
	rawToken := authtest.CreateTokenString(claims, privateKey)
	_, err := tokenValidator.Validate(rawToken)

	if assert.NotNil(t, err) {
		assert.Equal(t, validation.ErrorExpired, err.(*validation.Error).Code)
	}
}

func TestBadSignatureToken(t *testing.T) {
	_, publicKey, claims, attackerKey := setupValidationTest()
	tokenValidator := getTokenValidator(publicKey)

	rawToken := authtest.CreateTokenString(claims, attackerKey)
	_, err := tokenValidator.Validate(rawToken)

	if assert.NotNil(t, err) {
		assert.Equal(t, validation.ErrorValidation, err.(*validation.Error).Code)
	}
}

func TestBadAlgorithmToken(t *testing.T) {
	privateKey, publicKey, claims, _ := setupValidationTest()
	tokenValidator := getTokenValidator(publicKey)

	rawToken := authtest.CreateTokenStringWithAlg("HS256", claims, privateKey)
	_, err := tokenValidator.Validate(rawToken)

	if assert.NotNil(t, err) {
		assert.Equal(t, validation.ErrorValidation, err.(*validation.Error).Code)
	}
}

func TestNoAlgorithmToken(t *testing.T) {
	privateKey, publicKey, claims, _ := setupValidationTest()
	tokenValidator := getTokenValidator(publicKey)

	rawToken := authtest.CreateTokenStringWithAlg("none", claims, privateKey)
	_, err := tokenValidator.Validate(rawToken)

	if assert.NotNil(t, err) {
		assert.Equal(t, validation.ErrorValidation, err.(*validation.Error).Code)
	}
}
