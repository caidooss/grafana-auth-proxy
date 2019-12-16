package grafana_auth_proxy

import (
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/caido/grafana-auth-proxy/pkg/extraction"
	"github.com/caido/grafana-auth-proxy/pkg/identity"
	"github.com/caido/grafana-auth-proxy/pkg/validation"
	"github.com/dgrijalva/jwt-go"
)

const (
	grafanaAuthHeader = "X-WEBAUTH-USER"
)

type RequestsHandler struct {
	servedUrl        *url.URL
	tokenExtractor   *extraction.TokenExtractor
	tokenValidator   *validation.TokenValidator
	identityProvider identity.Provider
}

func (rh *RequestsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Allow free access to the health API used by load balancers
	if r.RequestURI == "/api/health" {
		proxy := httputil.NewSingleHostReverseProxy(rh.servedUrl)
		proxy.ServeHTTP(w, r)
		return
	}

	// Extract the token
	rawToken, err := rh.tokenExtractor.Extract(r)
	if err != nil {
		rh.unauthorizedHandler(w, r)
		return
	}

	// Validate the token
	token, err := rh.tokenValidator.Validate(rawToken)
	if err != nil {
		rh.unauthorizedHandler(w, r)
		return
	}

	rh.serveHandler(token, w, r)
}

func (rh *RequestsHandler) serveHandler(token *jwt.Token, w http.ResponseWriter, r *http.Request) {
	// Get the user identity
	userId, err := rh.identityProvider.Identify(token.Claims.(jwt.MapClaims))
	if err != nil {
		rh.unauthorizedHandler(w, r)
		return
	}

	// Create the reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(rh.servedUrl)

	// Update the headers to allow for SSL redirection
	r.URL.Host = rh.servedUrl.Host
	r.URL.Scheme = rh.servedUrl.Scheme
	r.Header.Set("X-Forwarded-Host", r.Header.Get("Host"))
	r.Header.Set(grafanaAuthHeader, userId)
	r.Host = rh.servedUrl.Host

	proxy.ServeHTTP(w, r)
}

func (rh *RequestsHandler) unauthorizedHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Unauthorized", 401)
}
