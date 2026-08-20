package web

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/invopop/gobl"

	"github.com/invopop/gobl.kyb/internal/domain"
)

// handleInbox processes a verification request: the subject's
// registered envelope POSTed to the verifier's inbox. The handler
// parses the envelope and delegates to the domain, which verifies the
// signatures, decides whether the party is verifiable at all, opens a
// provider session and emails its link.
//
// All of that happens before the response, so a 202 means the check is
// genuinely under way and a refusal reaches the sender rather than only
// the logs. That matters more here than it would elsewhere: opening a
// session spends money, so the caller has to learn immediately whether
// it happened.
func handleInbox(s *domain.Setup, log *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, inboxMaxBody)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				log.Warn("inbox.rejected", "reason", "body_too_large", "remote", r.RemoteAddr)
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			log.Warn("inbox.rejected", "reason", "read_body", "remote", r.RemoteAddr, "error", err.Error())
			http.Error(w, "could not read body", http.StatusBadRequest)
			return
		}
		env := new(gobl.Envelope)
		if err := json.Unmarshal(body, env); err != nil {
			log.Warn("inbox.rejected", "reason", "bad_body", "remote", r.RemoteAddr)
			http.Error(w, "invalid envelope JSON", http.StatusBadRequest)
			return
		}
		// The requester (token iss) may be a trusted intermediary
		// transmitting on the subject's behalf; the domain resolves
		// the subject from the envelope's own signature.
		if _, err := s.Verifications().Receive(r.Context(), env); err != nil {
			writeError(w, err)
			return
		}
		log.Info("inbox.received", "requester", string(requesterFrom(r.Context())))
		w.WriteHeader(http.StatusAccepted)
	}
}
