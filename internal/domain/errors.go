package domain

import (
	"fmt"

	"github.com/invopop/gobl/cbc"
)

// Error is the standard error type returned by domain methods. Its
// kind lets transport adapters (e.g. interfaces/web) map a failure
// onto the right protocol status without inspecting the message.
type Error struct {
	kind cbc.Key
	msg  string
}

var (
	// ErrValidation is returned when input data fails a business
	// rule (malformed envelope, wrong document type, ...).
	ErrValidation = NewError("validation")
	// ErrUnauthorized is returned when an envelope's signature or
	// audience does not authenticate the caller.
	ErrUnauthorized = NewError("unauthorized")
	// ErrForbidden is returned when an authenticated caller does not
	// qualify (e.g. a registration from an address that publishes no
	// public identity).
	ErrForbidden = NewError("forbidden")
	// ErrNotFound is returned when no record matches the request.
	ErrNotFound = NewError("not-found")
	// ErrConflict is returned when an optimistic-concurrency write
	// loses a race; callers should re-read and retry.
	ErrConflict = NewError("conflict")
	// ErrGone is returned when a status link has expired: the resource
	// existed but is no longer usable, and the subject must re-register
	// to receive a fresh one.
	ErrGone = NewError("gone")
	// ErrUnavailable is returned when a remote dependency needed to
	// process the request (a key or who endpoint) could not be
	// reached: a transient condition the caller should retry.
	ErrUnavailable = NewError("unavailable")
	// ErrInternal wraps an unexpected failure.
	ErrInternal = NewError("internal")
)

// NewError instantiates a new error of the given kind.
func NewError(kind cbc.Key) *Error {
	return &Error{kind: kind}
}

func (e *Error) copy() *Error {
	ne := new(Error)
	*ne = *e
	return ne
}

// WithMessage returns a copy of the error carrying a formatted message.
func (e *Error) WithMessage(message string, args ...any) *Error {
	ne := e.copy()
	if len(args) > 0 {
		ne.msg = fmt.Sprintf(message, args...)
	} else {
		ne.msg = message
	}
	return ne
}

// WithCause returns a copy of the error carrying the cause's message,
// unless the cause is already a domain Error, in which case it is
// returned unchanged.
func (e *Error) WithCause(cause error) *Error {
	if de, ok := cause.(*Error); ok {
		return de
	}
	ne := e.copy()
	if cause != nil {
		ne.msg = cause.Error()
	}
	return ne
}

// Error provides the string representation meant for log output.
func (e *Error) Error() string {
	if e.msg == "" {
		return e.kind.String()
	}
	return fmt.Sprintf("%s: %s", e.kind, e.msg)
}

// Is matches against another domain Error by kind.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	if !ok {
		return false
	}
	return e.kind == t.kind
}

// Kind returns the error's kind key.
func (e *Error) Kind() cbc.Key { return e.kind }

// Message returns the error's message, if set.
func (e *Error) Message() string { return e.msg }
