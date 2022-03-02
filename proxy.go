package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"

	"github.com/caido/grafana-auth-proxy/pkg/extraction"
	"github.com/caido/grafana-auth-proxy/pkg/grafana"
	"github.com/caido/grafana-auth-proxy/pkg/identity"
	"github.com/caido/grafana-auth-proxy/pkg/validation"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
)

const (
	grafanaAuthHeader = "X-WEBAUTH-USER"
)

type RequestsHandler struct {
	ServedUrl         *url.URL
	TokenExtractor    *extraction.TokenExtractor
	TokenValidator    *validation.TokenValidator
	IdentityProviders map[string]identity.Provider
	GrafanaClient     *grafana.GrafanaClient
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
	email, err := rh.IdentityProviders["user_claim"].Identify(token.Claims.(jwt.MapClaims))
	if err != nil {
		rh.unauthorizedHandler(w, r)
		return
	}
	orgName, err := rh.IdentityProviders["org_claim"].Identify(token.Claims.(jwt.MapClaims))
	if err != nil {
		rh.unauthorizedHandler(w, r)
		return
	}
	role, err := rh.IdentityProviders["role_claim"].Identify(token.Claims.(jwt.MapClaims))
	if err != nil {
		rh.unauthorizedHandler(w, r)
		return
	}

	orgId, err := rh.GrafanaClient.GetOrgByName(orgName)
	if err != nil {
		if errors.Is(err, grafana.ErrOrgNotFound) {
			orgId, err = rh.GrafanaClient.CreateOrg(orgName)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			log.Fatal(err)
		}
	}
	userId, err := rh.GrafanaClient.GetUserByEmail(email)
	if err != nil {
		if errors.Is(err, grafana.ErrUserNotFound) {
			uniquePass := uuid.New() // Password is not used for authentication.
			userId, err = rh.GrafanaClient.CreateUser(email, email, uniquePass.String(), orgId)
			if err != nil {
				log.Fatal(err)
			}
			err = rh.GrafanaClient.UpdateUserOrgRole(userId, orgId, role)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			log.Fatal(err)
		}
	} else {
		userInOrg, err := rh.GrafanaClient.UserInOrg(email, orgId)
		if err != nil {
			log.Fatal(err)
		}
		if !userInOrg {
			err = rh.GrafanaClient.AddUserToOrg(email, orgId, role)
			if err != nil {
				log.Fatal(err)
			}
		}
	}
	err = rh.GrafanaClient.SwitchUserContext(userId, orgId)
	if err != nil {
		log.Fatal(err)
	}

	// Create the reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(rh.ServedUrl)

	// Update the headers to allow for SSL redirection
	r.URL.Host = rh.ServedUrl.Host
	r.URL.Scheme = rh.ServedUrl.Scheme
	r.Header.Set("X-Forwarded-Host", r.Header.Get("Host"))
	r.Header.Set(grafanaAuthHeader, email)
	r.Header.Set("X-Grafana-Org-Id", strconv.Itoa(int(orgId))) // Doesn't appear to have an effect
	r.Host = rh.ServedUrl.Host

	proxy.ServeHTTP(w, r)
}

func (rh *RequestsHandler) unauthorizedHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	fmt.Fprintf(w, `{"message": "Unauthorized"}`)
}
