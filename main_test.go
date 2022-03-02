package main

import (
	"flag"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/urfave/cli/v2"

	"github.com/caido/grafana-auth-proxy/pkg/authtest"
)

func setupTestJWKServer() (string, func()) {
	publicKey := authtest.LoadPublicKey()
	jwk := authtest.GetRawRS256Jwk(publicKey)

	jwkServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(jwk))
	}))

	return jwkServer.URL, jwkServer.Close
}

func setupTestFlagSet(backendURL string, jwkURL string) *flag.FlagSet {
	set := flag.NewFlagSet("test", 0)
	set.Int("port", 5000, "")
	set.String("url", backendURL, "")
	set.String("jwk", jwkURL, "")
	set.Bool("cookieAuth", true, "")
	set.String("cookie", cookieName, "")
	set.Var(cli.NewStringSlice(authtest.Algorithm), "algorithms", "")
	set.String("audience", authtest.Audience, "")
	set.String("issuer", authtest.Issuer, "")
	set.String("user_claim", authtest.UserClaim, "")
	set.String("org_claim", authtest.OrgClaim, "")
	set.String("role_claim", authtest.RoleClaim, "")
	return set
}

func TestCreateRequestsHandler(t *testing.T) {
	backendURL, closeBackend := setupTestBackendServer()
	jwkURL, closeJwk := setupTestJWKServer()
	defer closeBackend()
	defer closeJwk()

	set := setupTestFlagSet(backendURL, jwkURL)
	context := cli.NewContext(&cli.App{}, set, nil)

	requestHandler, err := createRequestsHandler(context)
	assert.Nil(t, err)

	req, _ := http.NewRequest("GET", "/test", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: setupTestToken()})

	// Send the request
	rr := httptest.NewRecorder()
	requestHandler.ServeHTTP(rr, req)

	assert.Equal(t, rr.Code, http.StatusOK)
	assert.Equal(t, rr.Body.String(), "user@testing.io")
}
