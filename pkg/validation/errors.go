package validation

import (
	"fmt"
)

type ErrorCode int

const (
	ErrorToken ErrorCode = iota
	ErrorAudience
	ErrorIssuer
	ErrorExpired
	ErrorValidation
	ErrorNilAlg
	ErrorNilKid
	ErrorUnsupportedAlg
)

type Error struct {
	Message string
	Code    ErrorCode
}

func (e *Error) Error() string {
	return fmt.Sprintf("Code [%v] : %v", e.Code, e.Message)
}
