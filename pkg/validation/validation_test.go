package validation

import (
	"crypto/rsa"
	"testing"
	"time"

	"github.com/caido/grafana-auth-proxy/pkg/authtest"

	"github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/stretchr/testify/assert"
)

func setupValidationTest() (*rsa.PrivateKey, *rsa.PublicKey, jwt.MapClaims, *rsa.PrivateKey) {
	privateKey := authtest.LoadRSAPrivateKeyFromDisk("testdata/sample_key")
	publicKey := authtest.LoadRSAPublicKeyFromDisk("testdata/sample_key.pub")
	attackerKey := authtest.LoadRSAPrivateKeyFromDisk("testdata/attacker_key")
	claims := authtest.GetDefaultClaims()
	return privateKey, publicKey, claims, attackerKey
}

func getTokenValidator(publicKey *rsa.PublicKey) *TokenValidator {
	rawKeys := authtest.GetRawRS256Jwk(publicKey)
	keys, _ := jwk.ParseString(rawKeys)
	return NewTokenValidator(
		keys,
		[]string{authtest.Algorithm},
		authtest.Audience,
		authtest.Issuer,
	)
}

func TestValidToken(t *testing.T) {
	privateKey, publicKey, claims, _ := setupValidationTest()
	tokenValidator := getTokenValidator(publicKey)

	rawToken := authtest.MakeSampleTokenString(claims, privateKey)
	token, err := tokenValidator.Validate(rawToken)

	assert.Nil(t, err)
	assert.NotNil(t, token)
}

func TestBadIssuerToken(t *testing.T) {
	privateKey, publicKey, claims, _ := setupValidationTest()
	tokenValidator := getTokenValidator(publicKey)

	claims["iss"] = "bad_issuer"
	rawToken := authtest.MakeSampleTokenString(claims, privateKey)
	_, err := tokenValidator.Validate(rawToken)

	if assert.NotNil(t, err) {
		assert.Equal(t, ErrorIssuer, err.(*Error).Code)
	}
}

func TestBadAudienceToken(t *testing.T) {
	privateKey, publicKey, claims, _ := setupValidationTest()
	tokenValidator := getTokenValidator(publicKey)

	claims["aud"] = "bad_audience"
	rawToken := authtest.MakeSampleTokenString(claims, privateKey)
	_, err := tokenValidator.Validate(rawToken)

	if assert.NotNil(t, err) {
		assert.Equal(t, ErrorAudience, err.(*Error).Code)
	}
}

func TestExpiredToken(t *testing.T) {
	privateKey, publicKey, claims, _ := setupValidationTest()
	tokenValidator := getTokenValidator(publicKey)

	claims["iat"] = time.Now().Unix() - 300
	claims["exp"] = time.Now().Unix() - 30
	rawToken := authtest.MakeSampleTokenString(claims, privateKey)
	_, err := tokenValidator.Validate(rawToken)

	if assert.NotNil(t, err) {
		assert.Equal(t, ErrorExpired, err.(*Error).Code)
	}
}

func TestBadSignatureToken(t *testing.T) {
	_, publicKey, claims, attackerKey := setupValidationTest()
	tokenValidator := getTokenValidator(publicKey)

	rawToken := authtest.MakeSampleTokenString(claims, attackerKey)
	_, err := tokenValidator.Validate(rawToken)

	if assert.NotNil(t, err) {
		assert.Equal(t, ErrorValidation, err.(*Error).Code)
	}
}

func TestBadAlgorithmToken(t *testing.T) {
	privateKey, publicKey, claims, _ := setupValidationTest()
	tokenValidator := getTokenValidator(publicKey)

	rawToken := authtest.MakeSampleTokenStringWithAlg("HS256", claims, privateKey)
	_, err := tokenValidator.Validate(rawToken)

	if assert.NotNil(t, err) {
		assert.Equal(t, ErrorValidation, err.(*Error).Code)
	}
}

func TestNoAlgorithmToken(t *testing.T) {
	privateKey, publicKey, claims, _ := setupValidationTest()
	tokenValidator := getTokenValidator(publicKey)

	rawToken := authtest.MakeSampleTokenStringWithAlg("none", claims, privateKey)
	_, err := tokenValidator.Validate(rawToken)

	if assert.NotNil(t, err) {
		assert.Equal(t, ErrorValidation, err.(*Error).Code)
	}
}

func TestStringInArray(t *testing.T) {
	var array = []string{"a", "b", "c"}

	// exist in array tests
	if !stringInSlice("a", array) {
		t.Error("String \"a\" should be in array")
	}

	if !stringInSlice("b", array) {
		t.Error("String \"b\" should be in array")
	}

	if !stringInSlice("c", array) {
		t.Error("String \"c\" should be in array")
	}

	// not in array tests
	if stringInSlice("not in array", array) {
		t.Error("Input string is not supposed to be in array")
	}

	if stringInSlice("ab", array) {
		t.Error("Input string is not supposed to be in array")
	}
}
