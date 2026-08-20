// Package web is the HTTP transport adapter for the KYB verification
// service. It exposes the standard GOBL Net well-known endpoints
// (inbox / who / keys / jwks), the provider callback, and the
// human-facing status page behind the emailed link.
//
// Three different authentication schemes meet here, and they are not
// interchangeable. The who and inbox endpoints take a bearer request
// token (spec §5.5), because their callers are GOBL Net participants.
// Key discovery is open, so that verifying a token never recurses. The
// provider callback carries no token at all — a KYB vendor cannot mint
// one — and is authenticated by the payload signature its own package
// verifies. The status page is authenticated by the unguessable token
// in its URL.
//
// Handlers stay thin: parse, delegate to the domain, map domain errors
// onto status codes.
package web

import (
	"errors"
	"log/slog"
	"net/http"

	goblnet "github.com/invopop/gobl/net"

	"github.com/invopop/gobl.kyb/internal/domain"
)

// inboxMaxBody caps the request body read by the inbox handler.
const inboxMaxBody = 1 << 20 // 1 MiB

// NewMux constructs the HTTP request multiplexer for the verification
// service. The returned handler is wrapped in the structured
// access-log middleware.
func NewMux(setup *domain.Setup, log *slog.Logger) http.Handler {
	if log == nil {
		log = slog.Default()
	}
	mux := http.NewServeMux()

	mux.HandleFunc("POST "+goblnet.InboxPath, requireAuth(setup, log, handleInbox(setup, log)))
	mux.HandleFunc("GET "+goblnet.WhoPath, requireAuth(setup, log, handleWho(setup, log)))
	mux.HandleFunc("GET "+goblnet.KeysPath+"/{kid}", handleKey(setup, log))
	mux.HandleFunc("GET "+goblnet.JWKSPath, handleJWKS(setup, log))
	mux.HandleFunc("POST "+setup.WebhookPath(), handleWebhook(setup, log))
	mux.HandleFunc("GET /status/{token}", handleStatus(setup, log))
	mux.HandleFunc("GET /healthz", handleHealth())

	return withAccessLog(log, mux)
}

// writeJSON writes body as application/json with the given status.
func writeJSON(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// writeError maps a domain error onto an HTTP status + message. Any
// non-domain error is treated as an internal failure.
func writeError(w http.ResponseWriter, err error) {
	var de *domain.Error
	if !errors.As(err, &de) {
		de = domain.ErrInternal.WithCause(err)
	}
	msg := de.Message()
	if msg == "" {
		msg = de.Error()
	}
	// Map the status from the resolved domain error so it always matches
	// the message being returned.
	http.Error(w, msg, statusForError(de))
}

// statusForError resolves the HTTP status for a domain error kind.
func statusForError(err error) int {
	switch {
	case errors.Is(err, domain.ErrValidation):
		return http.StatusUnprocessableEntity
	case errors.Is(err, domain.ErrUnauthorized):
		return http.StatusUnauthorized
	case errors.Is(err, domain.ErrForbidden):
		return http.StatusForbidden
	case errors.Is(err, domain.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, domain.ErrConflict):
		return http.StatusConflict
	case errors.Is(err, domain.ErrGone):
		return http.StatusGone
	case errors.Is(err, domain.ErrUnavailable):
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

func handleHealth() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, []byte(`{"status":"ok"}`))
	}
}
