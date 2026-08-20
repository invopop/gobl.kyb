package web

import (
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/invopop/gobl.kyb/internal/domain"
)

// webhookMaxBody caps the callback body. Provider decisions are
// verbose but nowhere near this.
const webhookMaxBody = 256 << 10 // 256 KiB

// handleWebhook receives provider callbacks.
//
// The response policy is the opposite of the inbox's, and deliberately
// so. A provider retries a callback once or twice and then drops it
// forever, so a status code is not a way to express an opinion — it is
// a choice about whether this update survives at all.
//
//   - Anything durably recorded answers 200, including payloads we do
//     not understand. Rejecting an unfamiliar event type would spend
//     the provider's two retries on something no retry can fix.
//   - Only a persistence failure answers 5xx, because that is the one
//     case where retrying does useful work.
//   - A forged or stale signature answers 401. It is not a delivery we
//     want repeated.
//
// Everything that is neither recorded nor retried is caught by the
// reconciler, which polls the provider directly. That is the real
// safety net; this endpoint is only the fast path.
func handleWebhook(setup *domain.Setup, log *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// The signature is computed over the payload, so the raw bytes
		// have to be read before anything is allowed to decode them.
		r.Body = http.MaxBytesReader(w, r.Body, webhookMaxBody)
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				log.Warn("webhook.rejected", "reason", "too_large", "limit", webhookMaxBody)
				http.Error(w, "callback body too large", http.StatusRequestEntityTooLarge)
				return
			}
			log.Warn("webhook.rejected", "reason", "unreadable", "error", err.Error())
			http.Error(w, "could not read callback body", http.StatusBadRequest)
			return
		}

		if err := setup.Verifications().HandleEvent(r.Context(), raw, r.Header); err != nil {
			// Only a genuine internal failure is worth a retry; the
			// domain already distinguishes them.
			if errors.Is(err, domain.ErrInternal) {
				writeError(w, err)
				return
			}
			if errors.Is(err, domain.ErrUnauthorized) {
				writeError(w, err)
				return
			}
			// Anything else — an unroutable reference, an unknown
			// address, a payload shape we do not recognise — is
			// recorded and acknowledged. Retrying will not change it.
			log.Warn("webhook.ignored", "error", err.Error())
		}
		w.WriteHeader(http.StatusOK)
	}
}
