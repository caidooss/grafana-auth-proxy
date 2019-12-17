package extraction_test

import (
	"net/http"
	"testing"

	"github.com/caido/grafana-auth-proxy/pkg/extraction"
	"github.com/stretchr/testify/assert"
)

const (
	cookieName  = "CookieMonster"
	cookieValue = "SuperCookieToken"
)

func TestCookieExtractor(t *testing.T) {
	cookieExtractor := extraction.NewCookieExtractor(cookieName)
	req, _ := http.NewRequest("GET", "/test", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: cookieValue})

	token, err := cookieExtractor.Extract(req)

	assert.Nil(t, err)
	assert.Equal(t, token, cookieValue)
}

func TestCookieExtractorMissingCookie(t *testing.T) {
	cookieExtractor := extraction.NewCookieExtractor(cookieName)
	req, _ := http.NewRequest("GET", "/test", nil)

	token, err := cookieExtractor.Extract(req)

	assert.NotNil(t, err)
	assert.Empty(t, token)
}

func TestCookieExtractorOtherCookie(t *testing.T) {
	cookieExtractor := extraction.NewCookieExtractor(cookieName)
	req, _ := http.NewRequest("GET", "/test", nil)
	req.AddCookie(&http.Cookie{Name: "OtherCookieName", Value: cookieValue})

	token, err := cookieExtractor.Extract(req)

	assert.NotNil(t, err)
	assert.Empty(t, token)
}
