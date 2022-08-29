package saml

import (
	"fmt"
	"net/http"

	"github.com/pkg/errors"
)

var (
	ErrInvalidRequest         = &Error{Code: http.StatusBadRequest}
	ErrNotFound               = &Error{Code: http.StatusNotFound}
	ErrInvalidSAMLRequest     = ErrInvalidRequest.WithMessage("Invalid SAML Request")
	ErrUnknownServiceProvider = ErrNotFound.WithMessage("Unknown service provider")
	ErrUnknownACSEndpoint     = ErrNotFound.WithMessage("Unknown ACS endpoint")
)

type Error struct {
	Code    int
	Message string
	Err     error
}

func (e *Error) WithMessage(msg string) *Error {
	ne := *e
	ne.Message = msg
	return &ne
}

func (e *Error) WithMessagef(msg string, args ...interface{}) *Error {
	ne := *e
	ne.Message = fmt.Sprintf(msg, args...)
	return &ne
}

func (e *Error) Unwrap() error {
	return e.Err
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%d %s: %s", e.Code, e.Message, e.Err.Error())
	}

	return fmt.Sprintf("%d %s", e.Code, e.Message)
}

func (e *Error) WithError(err error) *Error {
	if e.Err != nil {
		err = errors.Wrapf(e.Err, "%s", err)
	}

	ne := *e
	ne.Err = errors.WithStack(err)

	return &ne
}

func (e *Error) WithErrorf(err error, msg string, args ...interface{}) *Error {
	if e.Err != nil {
		err = errors.Wrapf(e.Err, "%s", err)
	}

	ne := *e
	ne.Err = errors.WithStack(errors.Wrapf(err, msg, args...))

	return &ne
}
