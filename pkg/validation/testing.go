package validation

import (
	"crypto/rsa"
	"encoding/base64"
	"io/ioutil"
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

func LoadRSAPrivateKeyFromDisk(location string) *rsa.PrivateKey {
	keyData, e := ioutil.ReadFile(location)
	if e != nil {
		panic(e.Error())
	}

	key, e := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if e != nil {
		panic(e.Error())
	}

	return key
}

func LoadRSAPublicKeyFromDisk(location string) *rsa.PublicKey {
	keyData, e := ioutil.ReadFile(location)
	if e != nil {
		panic(e.Error())
	}

	key, e := jwt.ParseRSAPublicKeyFromPEM(keyData)
	if e != nil {
		panic(e.Error())
	}

	return key
}

func MakeSampleToken(kid string, c jwt.Claims, key interface{}) *jwt.Token {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	token.Header["kid"] = kid

	return token
}

func MakeSampleTokenString(c jwt.Claims, key interface{}) string {
	return MakeSampleTokenStringWithAlg("RS256", c, key)
}

func MakeSampleTokenStringWithAlg(alg string, c jwt.Claims, key interface{}) string {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	token.Header["kid"] = KeyId
	token.Header["alg"] = alg
	s, e := token.SignedString(key)

	if e != nil {
		panic(e.Error())
	}

	return s
}

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
