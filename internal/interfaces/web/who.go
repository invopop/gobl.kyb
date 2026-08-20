package web

import (
	"log/slog"
	"net/http"

	"github.com/invopop/gobl.kyb/internal/domain"
)

// whoCacheControl allows the authenticated caller to cache the static
// party envelope briefly; the response requires authorization so it
// must not land in shared caches. The TTL bounds how quickly key or
// party changes are observed by verifiers.
const whoCacheControl = "private, max-age=300"

// handleWho serves this verifier's identity to an authenticated
// requester: its own party envelope, self-signed, the same static
// document for every authorized caller.
func handleWho(s *domain.Setup, log *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := s.Identity().PartyEnvelope()
		if err != nil {
			log.Error("who.sign_failed", "error", err.Error())
			http.Error(w, "could not prepare identity", http.StatusInternalServerError)
			return
		}
		log.Info("who.served", "requester", string(requesterFrom(r.Context())))
		w.Header().Set("Cache-Control", whoCacheControl)
		writeJSON(w, http.StatusOK, body)
	}
}
