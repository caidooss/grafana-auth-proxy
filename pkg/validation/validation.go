package validation

import (
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwk"
)

type TokenValidator struct {
	keys       *jwk.Set
	algorithms []string
	audience   string
	issuer     string
}

func NewTokenValidator(keys *jwk.Set, algorithms []string, audience string, issuer string) *TokenValidator {
	return &TokenValidator{
		keys,
		algorithms,
		audience,
		issuer,
	}
}

func (tv *TokenValidator) Validate(tokenString string) (*jwt.Token, error) {
	// Extract token
	token, err := jwt.Parse(tokenString, tv.getTokenAssociatedPublicKey)
	if err != nil {
		switch err.(type) {
		case *jwt.ValidationError:
			validationError := err.(*jwt.ValidationError)
			errorMessage := validationError.Inner
			errorCode := validationError.Errors

			if errorCode == jwt.ValidationErrorExpired {
				errorM := fmt.Sprintf("TOKEN EXPIRED : error_message=\"%v\" error_code=%v", errorMessage, errorCode)
				return nil, &Error{errorM, ErrorExpired}
			} else {
				errorM := fmt.Sprintf("VALIDATION ERROR : error_message=\"%v\" error_code=%v", errorMessage, errorCode)
				return nil, &Error{errorM, ErrorValidation}
			}
		default:
			return nil, err
		}
	}

	// Ensure validity and claims (https://auth0.com/docs/api-auth/tutorials/verify-access-token)
	if !token.Valid {
		return token, &Error{"Token is invalid", ErrorToken}
	}

	var match bool
	tokenAudList, isList := token.Claims.(jwt.MapClaims)["aud"].([]interface{})
	if isList {
		for _, iaud := range tokenAudList {
			aud := iaud.(string)
			if aud == tv.audience {
				match = true
				break
			}
		}
	} else {
		aud := token.Claims.(jwt.MapClaims)["aud"].(string)
		if aud == tv.audience {
			match = true
		}
	}
	if !match {
		return token, &Error{"audience does not match", ErrorAudience}
	}

	tokenIssuer := token.Claims.(jwt.MapClaims)["iss"].(string)
	if tokenIssuer != tv.issuer {
		return token, &Error{"issuer does not match", ErrorIssuer}
	}

	return token, nil
}

func (tv *TokenValidator) getTokenAssociatedPublicKey(token *jwt.Token) (interface{}, error) {
	// Verify ALG: it should at least be not "none". We decided to restrict it further to a set of trusted algorithms.
	// See vulnerability: https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
	algHeader := token.Header["alg"]
	if algHeader == nil {
		return nil, &Error{"token ALG header is nil", ErrorNilAlg}
	}
	if !stringInSlice(algHeader.(string), tv.algorithms) {
		errorMessage := fmt.Sprintf("algorithm %v is not in accepted algoritmns (%v)", algHeader, tv.algorithms)
		return nil, &Error{errorMessage, ErrorUnsupportedAlg}
	}

	// Fetch keys associated with the KID
	kidHeader := token.Header["kid"]
	if kidHeader == nil {
		return nil, &Error{"token KID header is nil", ErrorNilKid}
	}

	keys := tv.keys.LookupKeyID(kidHeader.(string))
	if len(keys) == 0 {
		return nil, errors.New("failed to lookup key")
	}

	// Use the first key
	key, err := keys[0].Materialize()
	if err != nil {
		return nil, errors.New(fmt.Sprintf("failed to generate public key: %s", err))
	}

	return key.(*rsa.PublicKey), nil
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}
