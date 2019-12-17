package authtest

import "github.com/dgrijalva/jwt-go"

func CreateTokenString(c jwt.Claims, key interface{}) string {
	return CreateTokenStringWithAlg("RS256", c, key)
}

func CreateTokenStringWithAlg(alg string, c jwt.Claims, key interface{}) string {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	token.Header["kid"] = KeyId
	token.Header["alg"] = alg
	s, e := token.SignedString(key)

	if e != nil {
		panic(e.Error())
	}

	return s
}
