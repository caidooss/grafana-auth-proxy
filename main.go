package main

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/caido/grafana-auth-proxy/pkg/extraction"
	"github.com/caido/grafana-auth-proxy/pkg/grafana"
	"github.com/caido/grafana-auth-proxy/pkg/identity"
	"github.com/caido/grafana-auth-proxy/pkg/validation"
	"github.com/joho/godotenv"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/urfave/cli/v2"
)

func loadJwk(c *cli.Context) (*jwk.Set, error) {
	// Get JWK fetch URL
	jwkUrl := c.String("jwk")
	if jwkUrl == "" {
		return nil, errors.New("a JWK URL is required")
	}

	// Fetch JWK
	response, err := http.Get(jwkUrl)
	if err != nil {
		errorMessage := fmt.Sprintf("The HTTP request failed with error %s\n", err)
		return nil, errors.New(errorMessage)
	}

	// Decode JWK
	data, _ := ioutil.ReadAll(response.Body)
	set, err := jwk.ParseString(string(data))
	if err != nil {
		log.Printf("Failed to parse jwk token")
		return nil, err
	}

	return set, nil
}

func createRequestsHandler(c *cli.Context) (*RequestsHandler, error) {
	// Prepare token extractor
	extractors := make([]extraction.Extractor, 0, 2)

	cookieName := c.String("cookie")
	if c.Bool("cookieAuth") && cookieName != "" {
		extractors = append(extractors, extraction.NewCookieExtractor(cookieName))
		log.Printf("JWT Cookie name : %s", cookieName)
	}

	headerName := c.String("header")
	headerPrefix := c.String("prefix")
	if c.Bool("headerAuth") && headerName != "" && headerPrefix != "" {
		extractors = append(extractors, extraction.NewHeaderExtractor(headerName, headerPrefix))
		log.Printf("JWT Header name : %s", headerName)
		log.Printf("JWT Header prefix : %s", headerPrefix)
	}

	if len(extractors) == 0 {
		return nil, errors.New("must specify either cookie or header authentication")
	}

	tokenExtractor := extraction.NewTokenExtractor(extractors...)

	// Prepare token validator
	keys, err := loadJwk(c)
	if err != nil {
		return nil, err
	}

	algorithms := c.StringSlice("algorithms")
	if len(algorithms) == 0 {
		return nil, errors.New("a least one JWT algorithm is required")
	}

	audience := c.String("audience")
	if audience == "" {
		return nil, errors.New("a JWT audience is required")
	}

	issuer := c.String("issuer")
	if issuer == "" {
		return nil, errors.New("a JWT issuer is required")
	}

	log.Printf("JWT accepted algorithms : %v", algorithms)
	log.Printf("JWT accepted audience : %s", audience)
	log.Printf("JWT accepted issuer : %s", issuer)

	tokenValidator := validation.NewTokenValidator(keys, algorithms, audience, issuer)

	// Prepare identity providers
	identityProviders := make(map[string]identity.Provider)
	userClaimName := c.String("user_claim")
	if userClaimName == "" {
		return nil, errors.New("a JWT Grafana user claim is required")
	}

	log.Printf("JWT Grafana authentication user claim : %s", userClaimName)

	identityProviders["user_claim"] = identity.NewTokenProvider(userClaimName)

	orgClaimName := c.String("org_claim")
	if orgClaimName == "" {
		return nil, errors.New("a JWT Grafana org claim is required")
	}

	log.Printf("JWT Grafana authentication org claim : %s", orgClaimName)

	identityProviders["org_claim"] = identity.NewTokenProvider(orgClaimName)

	roleClaimName := c.String("role_claim")
	if roleClaimName == "" {
		return nil, errors.New("a JWT Grafana role claim is required")
	}

	log.Printf("JWT Grafana authentication role claim : %s", roleClaimName)

	identityProviders["role_claim"] = identity.NewTokenProvider(roleClaimName)

	// Prepare requests handler
	rawURL := c.String("url")
	if rawURL == "" {
		return nil, errors.New("an URL is required")
	}

	servedUrl, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}

	grafanaClient := grafana.NewGrafanaClient(c.String("admin_username"), c.String("admin_password"), "http://localhost:3000")

	log.Printf("Proxy serving : %s", servedUrl)

	requestsHandler := &RequestsHandler{servedUrl, tokenExtractor, tokenValidator, identityProviders, grafanaClient}

	return requestsHandler, nil
}

func launchProxy(c *cli.Context) error {
	// Build requests handler
	requestsHandler, err := createRequestsHandler(c)
	if err != nil {
		return err
	}

	// Find port
	port := c.Int("port")
	if port == 0 {
		return errors.New("a port is required")
	}

	log.Printf("Proxy running on port : %d", port)

	tlsCert := c.String("tls_cert")
	if tlsCert == "" {
		return errors.New("a TLS certificate is required")
	}
	tlsKey := c.String("tls_key")
	if tlsKey == "" {
		return errors.New("a TLS key is required")
	}

	addr := c.String("addr")
	if addr == "" {
		addr = ":"
	} else {
		if !strings.HasSuffix(addr, ":") {
			addr += ":"
		}
	}

	// Start server
	server := http.Server{Addr: addr + strconv.Itoa(port), Handler: requestsHandler}
	go func() {
		if err := server.ListenAndServeTLS(tlsCert, tlsKey); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	// Handle shutdown
	select {
	case <-c.Context.Done():
		return server.Shutdown(c.Context)
	}
}

func main() {
	var err error

	// Load .env file
	err = godotenv.Load(".env")
	if err != nil {
		log.Printf("Unable to load a .env file")
	}

	// Build the app
	app := &cli.App{
		Action: launchProxy,
		Flags: []cli.Flag{
			&cli.IntFlag{
				Name:     "port",
				Required: true,
				Usage:    "port used by the proxy",
				EnvVars:  []string{"PROXY_PORT"},
			},
			&cli.StringFlag{
				Name:     "url",
				Required: true,
				Usage:    "URL served by the proxy",
				EnvVars:  []string{"PROXY_SERVED_URL"},
			},
			&cli.StringFlag{
				Name:     "jwk",
				Required: true,
				Usage:    "URL to fetch the JWK from",
				EnvVars:  []string{"PROXY_JWK_FETCH_URL"},
			},
			&cli.BoolFlag{
				Name:    "cookieAuth",
				Value:   false,
				Usage:   "enable cookie authentication",
				EnvVars: []string{"PROXY_COOKIE_AUTH"},
			},
			&cli.StringFlag{
				Name:    "cookie",
				Usage:   "cookie to extract token from",
				EnvVars: []string{"PROXY_COOKIE"},
			},
			&cli.BoolFlag{
				Name:    "headerAuth",
				Value:   false,
				Usage:   "enable header authentication",
				EnvVars: []string{"PROXY_HEADER_AUTH"},
			},
			&cli.StringFlag{
				Name:    "header",
				Value:   "Bearer",
				Usage:   "header to extract token from",
				EnvVars: []string{"PROXY_HEADER"},
			},
			&cli.StringFlag{
				Name:    "prefix",
				Value:   "Bearer",
				Usage:   "header prefix to expect",
				EnvVars: []string{"PROXY_HEADER_PREFIX"},
			},
			&cli.StringSliceFlag{
				Name:    "algorithms",
				Usage:   "JWT algorithms to accept",
				Value:   cli.NewStringSlice("RS256"),
				EnvVars: []string{"PROXY_JWT_ALGORITHMS"},
			},
			&cli.StringFlag{
				Name:     "audience",
				Required: true,
				Usage:    "JWT audience to accept",
				EnvVars:  []string{"PROXY_JWT_AUDIENCE"},
			},
			&cli.StringFlag{
				Name:     "issuer",
				Required: true,
				Usage:    "JWT issuer to accept",
				EnvVars:  []string{"PROXY_JWT_ISSUER"},
			},
			&cli.StringFlag{
				Name:     "user_claim",
				Required: true,
				Usage:    "JWT user claim to use for Grafana authentication",
				EnvVars:  []string{"PROXY_JWT_GRAFANA_USER_CLAIM"},
			},
			&cli.StringFlag{
				Name:     "org_claim",
				Required: true,
				Usage:    "JWT org claim to use for Grafana authentication",
				EnvVars:  []string{"PROXY_JWT_GRAFANA_ORG_CLAIM"},
			},
			&cli.StringFlag{
				Name:     "role_claim",
				Required: true,
				Usage:    "JWT role claim to use for Grafana authentication",
				EnvVars:  []string{"PROXY_JWT_GRAFANA_ROLE_CLAIM"},
			},
			&cli.StringFlag{
				Name:     "admin_password",
				Required: true,
				Usage:    "Grafana admin password",
				EnvVars:  []string{"PROXY_GRAFANA_ADMIN_PASSWORD"},
			},
			&cli.StringFlag{
				Name:     "admin_username",
				Required: true,
				Usage:    "Grafana admin username",
				EnvVars:  []string{"PROXY_GRAFANA_ADMIN_USERNAME"},
			},
			&cli.StringFlag{
				Name:     "tls_cert",
				Required: true,
				Usage:    "TLS server certificate",
				EnvVars:  []string{"PROXY_TLS_CERT"},
			},
			&cli.StringFlag{
				Name:     "tls_key",
				Required: true,
				Usage:    "TLS server key",
				EnvVars:  []string{"PROXY_TLS_KEY"},
			},
			&cli.StringFlag{
				Name:     "addr",
				Required: false,
				Usage:    "Server address (default: localhost)",
				EnvVars:  []string{"PROXY_ADDR"},
			},
		},
	}

	// Handle signals
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigs
		os.Exit(1)
	}()

	// Run the app
	ctx, cancel := context.WithCancel(context.Background())
	err = app.RunContext(ctx, os.Args)
	if err != nil {
		log.Fatal(err)
	}

	// Handle graceful shutdown
	<-sigs
	cancel()
}
