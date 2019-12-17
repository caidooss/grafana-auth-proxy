package main

import (
	"fmt"
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
	ServedUrl        *url.URL
	TokenExtractor   *extraction.TokenExtractor
	TokenValidator   *validation.TokenValidator
	IdentityProvider identity.Provider
}

func (rh *RequestsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Allow free access to the health API used by load balancers
	if r.RequestURI == "/api/health" {
		proxy := httputil.NewSingleHostReverseProxy(rh.ServedUrl)
		proxy.ServeHTTP(w, r)
		return
	}

	// Extract the token
	rawToken, err := rh.TokenExtractor.Extract(r)
	if err != nil {
		rh.unauthorizedHandler(w, r)
		return
	}

	// Validate the token
	token, err := rh.TokenValidator.Validate(rawToken)
	if err != nil {
		rh.unauthorizedHandler(w, r)
		return
	}

	rh.serveHandler(token, w, r)
}

func (rh *RequestsHandler) serveHandler(token *jwt.Token, w http.ResponseWriter, r *http.Request) {
	// Get the user identity
	userId, err := rh.IdentityProvider.Identify(token.Claims.(jwt.MapClaims))
	if err != nil {
		rh.unauthorizedHandler(w, r)
		return
	}

	// Create the reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(rh.ServedUrl)

	// Update the headers to allow for SSL redirection
	r.URL.Host = rh.ServedUrl.Host
	r.URL.Scheme = rh.ServedUrl.Scheme
	r.Header.Set("X-Forwarded-Host", r.Header.Get("Host"))
	r.Header.Set(grafanaAuthHeader, userId)
	r.Host = rh.ServedUrl.Host

	proxy.ServeHTTP(w, r)
}

func (rh *RequestsHandler) unauthorizedHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	fmt.Fprintf(w, `{"message": "Unauthorized"}`)
}
