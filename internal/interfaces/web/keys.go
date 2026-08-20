package web

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/invopop/gobl.kyb/internal/domain"
)

// handleKey serves a single published key by kid.
func handleKey(s *domain.Setup, log *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		kid := r.PathValue("kid")
		key := s.Identity().FindKey(kid)
		if key == nil {
			log.Info("keys.lookup", "kid", kid, "found", false)
			http.Error(w, "key not found", http.StatusNotFound)
			return
		}
		body, err := json.Marshal(key)
		if err != nil {
			log.Error("keys.lookup_failed", "kid", kid, "error", err.Error())
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		log.Info("keys.lookup", "kid", kid, "found", true)
		writeJSON(w, http.StatusOK, body)
	}
}

// handleJWKS serves the full published JWK Set.
func handleJWKS(s *domain.Setup, log *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		body, err := s.Identity().JWKS()
		if err != nil {
			log.Error("jwks.served_failed", "error", err.Error())
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		log.Info("jwks.served", "count", len(s.Identity().PublicKeys()))
		writeJSON(w, http.StatusOK, body)
	}
}
