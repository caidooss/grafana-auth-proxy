package extraction

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

type headerExtractor struct {
	headerName   string
	headerPrefix string
}

func NewHeaderExtractor(headerName string, headerPrefix string) *headerExtractor {
	return &headerExtractor{
		headerName:   headerName,
		headerPrefix: strings.ToLower(headerPrefix),
	}
}

func (he *headerExtractor) Extract(r *http.Request) (string, error) {
	// Extract header
	header := r.Header.Get(he.headerName)
	if header == "" {
		return "", errors.New(fmt.Sprintf("no header %s", he.headerName))
	}

	// Extract token
	values := strings.Split(header, " ")
	if strings.ToLower(values[0]) != he.headerPrefix {
		return "", errors.New(fmt.Sprintf("header must start with %s", he.headerPrefix))
	} else if len(values) == 1 {
		return "", errors.New("token not found in header")
	} else if len(values) > 2 {
		return "", errors.New("too many parts found in header")
	}

	return values[1], nil
}
