package web

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	goblnet "github.com/invopop/gobl/net"

	"github.com/invopop/gobl.kyb/internal/domain"
)

// requesterKey is the context key under which requireAuth stores the
// verified requester address for downstream handlers.
type requesterKey struct{}

// requesterFrom returns the verified requester address stored by
// requireAuth, or "" when the request was not authenticated.
func requesterFrom(ctx context.Context) goblnet.Address {
	addr, _ := ctx.Value(requesterKey{}).(goblnet.Address)
	return addr
}

// requireAuth verifies the bearer request token (spec §5.5) on every
// request before handing off to next, rejecting failures with 401.
// The auth.rejected / handler log entries carrying the requester
// address double as the request audit log.
func requireAuth(s *domain.Setup, log *slog.Logger, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		requester, err := s.Identity().VerifyRequest(r.Context(), header)
		if err != nil {
			// A token that cannot be *checked* (the issuer's key
			// endpoint is unreachable) is not an invalid token:
			// answer 503 so the client retries.
			if errors.Is(err, goblnet.ErrUnavailable) {
				log.Warn("auth.rejected",
					"path", r.URL.Path,
					"reason", "token_unavailable",
					"remote", r.RemoteAddr,
					"error", err.Error(),
				)
				http.Error(w, "could not verify request token", http.StatusServiceUnavailable)
				return
			}
			reason := "token_invalid"
			switch {
			case header == "":
				reason = "token_missing"
			case errors.Is(err, goblnet.ErrTokenExpired):
				reason = "token_expired"
			}
			log.Warn("auth.rejected",
				"path", r.URL.Path,
				"reason", reason,
				"remote", r.RemoteAddr,
				"error", err.Error(),
			)
			http.Error(w, "a valid bearer request token is required", http.StatusUnauthorized)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), requesterKey{}, requester)))
	}
}
