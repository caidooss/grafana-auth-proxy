package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/caido/grafana-auth-proxy/pkg/authtest"
	"github.com/caido/grafana-auth-proxy/pkg/extraction"
	"github.com/caido/grafana-auth-proxy/pkg/identity"
	"github.com/caido/grafana-auth-proxy/pkg/validation"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/stretchr/testify/assert"
)

const (
	cookieName = "AuthCookie"
)

func setupTestBackendServer() (string, func()) {
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userId := r.Header.Get(grafanaAuthHeader)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(userId))
	}))

	return backendServer.URL, backendServer.Close
}

func setupTestRequestsHandler(servedUrl string) *RequestsHandler {
	// Extractor
	tokenExtractor := extraction.NewTokenExtractor(extraction.NewCookieExtractor(cookieName))

	// Validator
	publicKey := authtest.LoadPublicKey()
	rawKeys := authtest.GetRawRS256Jwk(publicKey)
	keys, _ := jwk.ParseString(rawKeys)
	tokenValidator := validation.NewTokenValidator(keys, []string{"RS256"}, authtest.Audience, authtest.Issuer)

	// Identity Provider
	ips := make(map[string]identity.Provider)
	ips["user_claim"] = identity.NewTokenProvider(authtest.UserClaim)
	ips["org_claim"] = identity.NewTokenProvider(authtest.OrgClaim)
	ips["role_claim"] = identity.NewTokenProvider(authtest.RoleClaim)

	backendURL, _ := url.Parse(servedUrl)
	return &RequestsHandler{
		ServedUrl:         backendURL,
		TokenExtractor:    tokenExtractor,
		TokenValidator:    tokenValidator,
		IdentityProviders: ips,
	}
}

func setupTestToken() string {
	claims := authtest.GetDefaultClaims()
	privateKey := authtest.LoadPrivateKey()
	token := authtest.CreateTokenString(claims, privateKey)
	return token
}

func TestRequestsHandlerValidRequest(t *testing.T) {
	// Prepare the backend and proxy
	backendURL, closeBackend := setupTestBackendServer()
	defer closeBackend()
	requestHandler := setupTestRequestsHandler(backendURL)

	// Prepare the request
	req, _ := http.NewRequest("GET", "/test", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: setupTestToken()})

	// Send the request
	rr := httptest.NewRecorder()
	requestHandler.ServeHTTP(rr, req)

	assert.Equal(t, rr.Code, http.StatusOK)
	assert.Equal(t, rr.Body.String(), "user@testing.io")
}

func TestRequestsHandlerBackendDown(t *testing.T) {
	// Prepare the proxy
	requestHandler := setupTestRequestsHandler("http://localhost:12345")

	// Prepare the request
	req, _ := http.NewRequest("GET", "/test", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: setupTestToken()})

	// Send the request
	rr := httptest.NewRecorder()
	requestHandler.ServeHTTP(rr, req)

	assert.Equal(t, rr.Code, http.StatusBadGateway)
}

func TestRequestsHandlerMissingAuthentication(t *testing.T) {
	// Prepare the proxy
	requestHandler := setupTestRequestsHandler("http://localhost:12345")

	// Prepare the request
	req, _ := http.NewRequest("GET", "/test", nil)

	// Send the request
	rr := httptest.NewRecorder()
	requestHandler.ServeHTTP(rr, req)

	assert.Equal(t, rr.Code, http.StatusUnauthorized)
}
