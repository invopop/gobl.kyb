package web

import (
	"html/template"
	"log/slog"
	"net/http"

	"github.com/invopop/gobl.kyb/internal/domain"
	"github.com/invopop/gobl.kyb/internal/domain/models"
)

// statusPage is the single template behind the emailed status link.
// One page, no external assets — the link has to work in any browser,
// including the locked-down ones businesses hand their finance staff.
var statusPage = template.Must(template.New("status").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>{{.Title}} — GOBL KYB</title>
<style>
  body { font-family: system-ui, sans-serif; margin: 0; background: #f5f5f4; color: #1c1917; }
  main { max-width: 34rem; margin: 4rem auto; padding: 2rem; background: #fff;
         border-radius: 0.5rem; box-shadow: 0 1px 3px rgba(0,0,0,.1); }
  h1 { font-size: 1.25rem; margin-top: 0; }
  code { background: #f5f5f4; padding: 0.1rem 0.3rem; border-radius: 0.25rem;
         word-break: break-all; }
  a.button { display: inline-block; background: #1c1917; color: #fff;
             border-radius: 0.375rem; padding: 0.6rem 1.2rem; text-decoration: none; }
  .note { color: #57534e; font-size: 0.875rem; }
</style>
</head>
<body>
<main>
<h1>{{.Title}}</h1>
<p>{{.Message}}</p>
{{if .ActionURL}}<p><a class="button" href="{{.ActionURL}}">Continue verification</a></p>{{end}}
<p class="note">Identity <code>{{.Address}}</code>, verified by
<code>{{.Verifier}}</code> for the registration authority
<code>{{.Authority}}</code>.</p>
</main>
</body>
</html>
`))

// statusView is what the page renders.
type statusView struct {
	Title     string
	Message   string
	ActionURL string
	Address   string
	Verifier  string
	Authority string
}

// handleStatus renders the current state of a verification behind its
// unguessable link.
//
// It never shows the registry data the provider returned, or which
// check failed. Whoever holds this link controls the party's published
// mailbox, which is not the same as being entitled to see a third
// party's registry record — and spelling out which comparison failed
// would tell anyone probing the service exactly what to adjust.
func handleStatus(setup *domain.Setup, log *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.PathValue("token")
		rec, err := setup.Verifications().Case(r.Context(), token)
		if err != nil {
			renderStatus(w, statusForError(err), statusView{
				Title:     "Verification not found",
				Message:   "This link is not valid, or it has expired. Start the verification again from your own platform to get a new one.",
				Verifier:  string(setup.Identity().Address()),
				Authority: string(setup.Verifications().Authority()),
			})
			return
		}
		view := viewFor(rec)
		view.Address = string(rec.Address)
		view.Verifier = string(setup.Identity().Address())
		view.Authority = string(setup.Verifications().Authority())
		renderStatus(w, http.StatusOK, view)
	}
}

// viewFor maps a case onto what its owner should be told.
func viewFor(rec *models.Verification) statusView {
	switch rec.Status {
	case models.StatusReceived, models.StatusAwaitingPayment:
		return statusView{
			Title:   "Preparing your verification",
			Message: "We are setting up the business verification. Check back in a moment.",
		}
	case models.StatusSessionOpen:
		return statusView{
			Title:     "Verification in progress",
			Message:   "Your business verification has been started but not yet completed. Use the button below to continue where you left off.",
			ActionURL: rec.Provider.URL,
		}
	case models.StatusInReview:
		return statusView{
			Title:   "Under review",
			Message: "Your submission is with an analyst. There is nothing further for you to do, and starting again will not speed it up — we will email you as soon as there is a result.",
		}
	case models.StatusMatching:
		return statusView{
			Title:   "Almost there",
			Message: "The checks are complete and we are finishing the last step. This usually takes a few seconds.",
		}
	case models.StatusApproved, models.StatusDeliveryFailed:
		return statusView{
			Title:   "Verified",
			Message: "Your business has been verified. We are delivering the endorsement to the registration authority; once it reaches your inbox, publish it at your identity endpoint to complete the process.",
		}
	case models.StatusDelivered:
		return statusView{
			Title:   "Verified",
			Message: "Your business has been verified and the endorsement has been delivered to the registration authority. One step remains and it is yours: publish the endorsed identity your platform received, so that other participants can see it.",
		}
	case models.StatusDeclined, models.StatusMismatch:
		return statusView{
			Title:   "Verification not completed",
			Message: "We were not able to complete this verification. Your identity is still registered and can receive documents, but it cannot send them. If you believe this is a mistake, reply to the email we sent and our team will look into it.",
		}
	case models.StatusExpired:
		return statusView{
			Title:   "Verification expired",
			Message: "This verification was started but never completed, and the link has expired. Run the verification step again from your own platform to start a new one.",
		}
	default: // error
		return statusView{
			Title:   "Something went wrong",
			Message: "We hit a problem with this verification and our team has been notified. Nothing further is required from you right now.",
		}
	}
}

// renderStatus writes the page. The response is never cached and never
// carries a referrer: the URL is the credential.
func renderStatus(w http.ResponseWriter, status int, view statusView) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(status)
	_ = statusPage.Execute(w, view)
}
