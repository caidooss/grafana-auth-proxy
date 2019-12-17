package extraction_test

import (
	"net/http"
	"testing"

	"github.com/caido/grafana-auth-proxy/pkg/extraction"
	"github.com/stretchr/testify/assert"
)

func TestTokenExtractorNoExtractor(t *testing.T) {
	tokenExtractor := extraction.NewTokenExtractor()

	req, _ := http.NewRequest("GET", "/test", nil)

	token, err := tokenExtractor.Extract(req)

	assert.NotNil(t, err)
	assert.Empty(t, token)
}

func TestTokenExtractorFirstUsed(t *testing.T) {
	tokenExtractor := extraction.NewTokenExtractor(
		extraction.NewCookieExtractor(cookieName),
		extraction.NewHeaderExtractor(headerName, headerPrefix),
	)

	req, _ := http.NewRequest("GET", "/test", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: cookieValue})
	req.Header.Add(headerName, headerPrefix+" "+headerValue)

	token, err := tokenExtractor.Extract(req)

	assert.Nil(t, err)
	assert.Equal(t, token, cookieValue)
}

func TestTokenExtractorFallback(t *testing.T) {
	tokenExtractor := extraction.NewTokenExtractor(
		extraction.NewCookieExtractor(cookieName),
		extraction.NewHeaderExtractor(headerName, headerPrefix),
	)

	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Add(headerName, headerPrefix+" "+headerValue)

	token, err := tokenExtractor.Extract(req)

	assert.Nil(t, err)
	assert.Equal(t, token, headerValue)
}
