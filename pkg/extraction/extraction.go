package extraction

import (
	"errors"
	"net/http"
)

type Extractor interface {
	Extract(*http.Request) (string, error)
}

type TokenExtractor struct {
	extractors []Extractor
}

func NewTokenExtractor(extractors ...Extractor) *TokenExtractor {
	return &TokenExtractor{
		extractors,
	}
}

func (te *TokenExtractor) Extract(r *http.Request) (string, error) {
	for _, extractor := range te.extractors {
		token, err := extractor.Extract(r)
		if err == nil {
			return token, nil
		}
	}
	return "", errors.New("unable to extract token")
}
