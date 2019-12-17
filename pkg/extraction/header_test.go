package extraction_test

import (
	"net/http"
	"testing"

	"github.com/caido/grafana-auth-proxy/pkg/extraction"
	"github.com/stretchr/testify/assert"
)

const (
	headerName   = "Authorization"
	headerPrefix = "Bearer"
	headerValue  = "SuperHeaderToken"
)

func TestHeaderExtractor(t *testing.T) {
	headerExtractor := extraction.NewHeaderExtractor(headerName, headerPrefix)

	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Add(headerName, headerPrefix+" "+headerValue)

	token, err := headerExtractor.Extract(req)

	assert.Nil(t, err)
	assert.Equal(t, token, headerValue)
}

func TestHeaderExtractorMissingHeader(t *testing.T) {
	headerExtractor := extraction.NewHeaderExtractor(headerName, headerPrefix)

	req, _ := http.NewRequest("GET", "/test", nil)

	token, err := headerExtractor.Extract(req)

	assert.NotNil(t, err)
	assert.Empty(t, token)
}

func TestHeaderExtractorOtherHeader(t *testing.T) {
	headerExtractor := extraction.NewHeaderExtractor(headerName, headerPrefix)

	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Add("MyOtherHeader", headerPrefix+" "+headerValue)

	token, err := headerExtractor.Extract(req)

	assert.NotNil(t, err)
	assert.Empty(t, token)
}

func TestHeaderExtractorCaseInsensitive(t *testing.T) {
	headerExtractor := extraction.NewHeaderExtractor(headerName, headerPrefix)

	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Add(headerName, "bearer "+headerValue)

	token, err := headerExtractor.Extract(req)

	assert.Nil(t, err)
	assert.Equal(t, token, headerValue)
}

func TestHeaderExtractorWrongPrefix(t *testing.T) {
	headerExtractor := extraction.NewHeaderExtractor(headerName, headerPrefix)

	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Add(headerName, "InvalidPrefix "+headerValue)

	token, err := headerExtractor.Extract(req)

	assert.NotNil(t, err)
	assert.Empty(t, token)
}

func TestHeaderExtractorNoToken(t *testing.T) {
	headerExtractor := extraction.NewHeaderExtractor(headerName, headerPrefix)

	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Add(headerName, "InvalidPrefix ")

	token, err := headerExtractor.Extract(req)

	assert.NotNil(t, err)
	assert.Empty(t, token)
}

func TestHeaderExtractorTooManyParts(t *testing.T) {
	headerExtractor := extraction.NewHeaderExtractor(headerName, headerPrefix)

	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Add(headerName, "InvalidPrefix "+headerValue+" SomeOtherValue")

	token, err := headerExtractor.Extract(req)

	assert.NotNil(t, err)
	assert.Empty(t, token)
}
