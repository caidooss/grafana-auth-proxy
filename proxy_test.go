package grafana_auth_proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/caido/grafana-auth-proxy/pkg/identity"
	"github.com/lestrrat-go/jwx/jwk"

	"github.com/caido/grafana-auth-proxy/pkg/validation"

	"github.com/caido/grafana-auth-proxy/pkg/extraction"
)

const (
	cookieName    = "AuthCookie"
	usernameClaim = "email"
)

func getRequestsHandler(servedUrl string) *RequestsHandler {
	// Extractor
	tokenExtractor := extraction.NewTokenExtractor(extraction.NewCookieExtractor(cookieName))

	// Validator
	publicKey := validation.LoadRSAPublicKeyFromDisk("pkg/validation/testdata/sample_key.pub")
	rawKeys := validation.GetRawRS256Jwk(publicKey)
	keys, _ := jwk.ParseString(rawKeys)
	tokenValidator := validation.NewTokenValidator(keys, []string{"RS256"}, validation.Audience, validation.Issuer)

	// Identity Provider
	identityProvider := identity.NewTokenProvider(usernameClaim)

	backendURL, _ := url.Parse(servedUrl)
	return &RequestsHandler{
		servedUrl:        backendURL,
		tokenExtractor:   tokenExtractor,
		tokenValidator:   tokenValidator,
		identityProvider: identityProvider,
	}
}

func getToken() string {
	claims := validation.GetDefaultClaims()
	privateKey := validation.LoadRSAPrivateKeyFromDisk("pkg/validation/testdata/sample_key")
	token := validation.MakeSampleTokenString(claims, privateKey)
	return token
}

func TestRequestsHandlerValidRequest(t *testing.T) {
	// Prepare the backend and proxy
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userId := r.Header.Get(grafanaAuthHeader)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(userId))
	}))
	defer backend.Close()
	requestHandler := getRequestsHandler(backend.URL)

	// Prepare the request
	req, _ := http.NewRequest("GET", "/test", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: getToken()})

	// Send the request
	rr := httptest.NewRecorder()
	requestHandler.ServeHTTP(rr, req)

	assert.Equal(t, rr.Code, http.StatusOK)
	assert.Equal(t, rr.Body.String(), "user@testing.io")
}

func TestRequestsHandlerBackendDown(t *testing.T) {
	// Prepare the proxy
	requestHandler := getRequestsHandler("http://localhost:123456")

	// Prepare the request
	req, _ := http.NewRequest("GET", "/test", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: getToken()})

	// Send the request
	rr := httptest.NewRecorder()
	requestHandler.ServeHTTP(rr, req)

	assert.Equal(t, rr.Code, http.StatusBadGateway)
}

func TestRequestsHandlerMissingAuthentication(t *testing.T) {
	// Prepare the proxy
	requestHandler := getRequestsHandler("http://localhost:123456")

	// Prepare the request
	req, _ := http.NewRequest("GET", "/test", nil)

	// Send the request
	rr := httptest.NewRecorder()
	requestHandler.ServeHTTP(rr, req)

	assert.Equal(t, rr.Code, http.StatusUnauthorized)
}
