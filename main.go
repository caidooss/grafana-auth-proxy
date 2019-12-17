package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"

	"github.com/caido/grafana-auth-proxy/pkg/extraction"
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

func launchProxy(c *cli.Context) error {
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
		return errors.New("must specify either cookie or header authentication")
	}

	tokenExtractor := extraction.NewTokenExtractor(extractors...)

	// Prepare token validator
	keys, err := loadJwk(c)
	if err != nil {
		return err
	}

	algorithms := c.StringSlice("algorithms")
	if len(algorithms) == 0 {
		return errors.New("a least one JWT algorithm is required")
	}

	audience := c.String("audience")
	if audience == "" {
		return errors.New("a JWT audience is required")
	}

	issuer := c.String("issuer")
	if issuer == "" {
		return errors.New("a JWT issuer is required")
	}

	log.Printf("JWT accepted algorithms : %v", algorithms)
	log.Printf("JWT accepted audience : %s", audience)
	log.Printf("JWT accepted issuer : %s", issuer)

	tokenValidator := validation.NewTokenValidator(keys, algorithms, audience, issuer)

	// Prepare identity provider
	claimName := c.String("claim")
	if claimName == "" {
		return errors.New("a JWT Grafana claim is required")
	}

	log.Printf("JWT Grafana authentication claim : %s", claimName)

	identityProvider := identity.NewTokenProvider(claimName)

	// Prepare requests handler
	rawURL := c.String("url")
	if rawURL == "" {
		return errors.New("an URL is required")
	}

	servedUrl, err := url.Parse(rawURL)
	if err != nil {
		return err
	}

	log.Printf("Proxy serving : %s", servedUrl)

	requestsHandler := &RequestsHandler{servedUrl, tokenExtractor, tokenValidator, identityProvider}

	// Launch the proxy
	port := c.Int("port")
	if port == 0 {
		return errors.New("a port is required")
	}

	log.Printf("Proxy running on port : %d", port)

	return http.ListenAndServe(":"+strconv.Itoa(port), requestsHandler)
}

func main() {
	var err error

	// Load .env file
	err = godotenv.Load(".env")
	if err != nil {
		log.Printf("Unable to load a .env file")
	}

	// Launch app
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
				Name:     "claim",
				Required: true,
				Usage:    "JWT claim to use for Grafana authentication",
				EnvVars:  []string{"PROXY_JWT_GRAFANA_CLAIM"},
			},
		},
	}

	err = app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
