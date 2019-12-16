package extraction

import "net/http"

type cookieExtractor struct {
	cookieName string
}

func NewCookieExtractor(cookieName string) *cookieExtractor {
	return &cookieExtractor{cookieName}
}

func (ce *cookieExtractor) Extract(r *http.Request) (string, error) {
	cookie, err := r.Cookie(ce.cookieName)
	if err != nil {
		return "", err
	}
	return cookie.Value, nil
}
