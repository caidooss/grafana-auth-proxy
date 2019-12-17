package authtest

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"time"

	"github.com/dgrijalva/jwt-go"
)

const (
	Issuer    = "https://testing.auth0.com/"
	Audience  = "https://api.testing.io/"
	Algorithm = "RS256"
	KeyId     = "SomeKeyId"
)

func GetDefaultClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"iss":   Issuer,
		"sub":   "r2dxgj8VwMEYweseSdTn2kZXRVGAtSYS@clients",
		"aud":   Audience,
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Unix() + 3600,
		"azp":   "r2dxgj8VwMEYweseSdTn2kZXRVGAtSYS",
		"gty":   "client-credentials",
		"email": "user@testing.io",
	}
}

func GetRawRS256Jwk(publicKey *rsa.PublicKey) string {
	return `{
       "keys":[
          {
             "alg":"RS256",
             "e":"` + base64encodeInt(publicKey.E) + `",
             "kid":"` + KeyId + `",
             "kty":"RSA",
             "n":"` + base64encodeBigInt(publicKey.N) + `",
             "use":"sig"
          }
       ]
    }`
}

func base64encodeInt(i int) string {
	bigInt := big.NewInt(int64(i))
	return base64encodeBigInt(bigInt)
}

func base64encodeBigInt(i *big.Int) string {
	// RFC7517 : base64url encoding of their big-endian representations. (https://tools.ietf.org/html/rfc7517#appendix-A.1)
	encoded := base64.RawURLEncoding.EncodeToString(i.Bytes())
	return encoded
}
