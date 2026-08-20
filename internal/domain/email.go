package domain

import (
	"context"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/invopop/gobl/org"

	"github.com/invopop/gobl.kyb/internal/domain/mailer"
	"github.com/invopop/gobl.kyb/internal/domain/models"
)

// The transactional emails. Plain text only: their job is to carry a
// link or an outcome, and text survives every client and spam-filter
// posture.
//
// One rule runs through all of them. A message to the subject never
// reveals what the registry returned, even when that is exactly what
// went wrong. Repeating the provider's data would leak it to whoever
// controls the address, and would tell anyone probing the service what
// it compares against. "We could not complete this, our team is
// looking" is all a customer needs; the detail goes to the operators.

var startText = template.Must(template.New("start").Parse(
	`Hello{{if .Name}} {{.Name}}{{end}},

A business verification for the GOBL Net identity "{{.Address}}" was
requested through the registration authority {{.Authority}}.

To complete it, open the link below and follow the steps. You will be
asked to confirm the company's registry details and to upload any
supporting documents the check needs.

  {{.SessionURL}}

If you did not request this verification, ignore this message and
nothing will change.

You can follow the progress of the verification here:

  {{.StatusURL}}

-- {{.Verifier}}
`))

var inReviewText = template.Must(template.New("in_review").Parse(
	`Hello{{if .Name}} {{.Name}}{{end}},

The business verification for "{{.Address}}" has been submitted and is
now with an analyst for review.

There is nothing further for you to do, and starting the verification
again will not speed it up. We will email you as soon as there is a
result.

  {{.StatusURL}}

-- {{.Verifier}}
`))

var approvedText = template.Must(template.New("approved").Parse(
	`Hello{{if .Name}} {{.Name}}{{end}},

The business verification for "{{.Address}}" has been completed
successfully.

The verification has been countersigned and sent to the registration
authority {{.Authority}}, which will deliver the endorsed identity back
to your own inbox. One step remains and it is yours: publish that
endorsed document at your identity endpoint. Until you do, other
participants will still see you as registered but unverified.

  {{.StatusURL}}

-- {{.Verifier}}
`))

var declinedText = template.Must(template.New("declined").Parse(
	`Hello{{if .Name}} {{.Name}}{{end}},

The business verification for "{{.Address}}" could not be completed.

Your identity remains registered with {{.Authority}} and can still
receive documents; it is not verified, so it cannot send them.

  {{.StatusURL}}

If you believe this is a mistake, reply to this message and our team
will look into it.

-- {{.Verifier}}
`))

var expiredText = template.Must(template.New("expired").Parse(
	`Hello{{if .Name}} {{.Name}}{{end}},

The business verification for "{{.Address}}" was started but never
completed, and the link has now expired.

Nothing has changed: your identity is still registered with
{{.Authority}}. To try again, run the verification step once more from
your own platform.

-- {{.Verifier}}
`))

var opsAlertText = template.Must(template.New("ops").Parse(
	`A verification needs attention.

  address:  {{.Address}}
  status:   {{.Status}}
  session:  {{.Session}}
  attempt:  {{.Attempt}}

  {{.Detail}}

Inspect with:  gobl.kyb status {{.Address}}
`))

// notifyStart sends the hosted verification link.
func (d *Verifications) notifyStart(ctx context.Context, rec *models.Verification) error {
	msg := d.render(rec, startText, "Verify the business behind "+string(rec.Address), map[string]string{
		"SessionURL": rec.Provider.URL,
	})
	return d.send(ctx, rec, msg)
}

// notifyInReview tells the subject the check is with an analyst.
//
// It exists to stop a well-meaning customer from starting again out of
// impatience: with a pay-per-check provider, a duplicate attempt is a
// duplicate bill.
func (d *Verifications) notifyInReview(ctx context.Context, rec *models.Verification) {
	msg := d.render(rec, inReviewText, "Verification of "+string(rec.Address)+" is under review", nil)
	_ = d.send(ctx, rec, msg)
}

// notifyApproved tells the subject the endorsement is on its way, and
// that publishing it is their step.
func (d *Verifications) notifyApproved(ctx context.Context, rec *models.Verification) {
	msg := d.render(rec, approvedText, "Verification of "+string(rec.Address)+" is complete", nil)
	_ = d.send(ctx, rec, msg)
}

// notifyDeclined tells the subject the check failed, without detail.
func (d *Verifications) notifyDeclined(ctx context.Context, rec *models.Verification) {
	msg := d.render(rec, declinedText, "Verification of "+string(rec.Address)+" was not completed", nil)
	_ = d.send(ctx, rec, msg)
}

// notifyMismatch uses the same wording as a decline. From the
// subject's side there is no useful difference, and spelling out that
// the registry data disagreed would hand a probe exactly the signal it
// is looking for.
func (d *Verifications) notifyMismatch(ctx context.Context, rec *models.Verification) {
	d.notifyDeclined(ctx, rec)
}

// notifyExpired tells the subject an abandoned session lapsed.
func (d *Verifications) notifyExpired(ctx context.Context, rec *models.Verification) {
	msg := d.render(rec, expiredText, "Verification of "+string(rec.Address)+" has expired", nil)
	_ = d.send(ctx, rec, msg)
}

// alertOps raises a case for a human. A mismatch is either bad party
// data or somebody trying to borrow another company's verification;
// both want eyes on them, and neither resolves itself.
func (d *Verifications) alertOps(ctx context.Context, rec *models.Verification, detail string) {
	if d.opsEmail == "" {
		return
	}
	var b strings.Builder
	_ = opsAlertText.Execute(&b, map[string]string{
		"Address": string(rec.Address),
		"Status":  string(rec.Status),
		"Session": rec.Provider.ID,
		"Attempt": strconv.Itoa(rec.Attempt),
		"Detail":  detail,
	})
	sendCtx, cancel := context.WithTimeout(ctx, deliveryTimeout)
	defer cancel()
	if err := d.mailer.Send(sendCtx, mailer.Message{
		To:      d.opsEmail,
		Subject: "[gobl.kyb] " + string(rec.Status) + ": " + string(rec.Address),
		Text:    b.String(),
	}); err != nil {
		d.log.Warn("ops_alert.send_failed", "address", string(rec.Address), "error", err.Error())
	}
}

// render builds a message from a template, filling in the fields every
// template shares.
func (d *Verifications) render(rec *models.Verification, tpl *template.Template, subject string, extra map[string]string) mailer.Message {
	name := partyName(rec)
	data := map[string]string{
		"Name":      name,
		"Address":   string(rec.Address),
		"Authority": string(d.opts.Authority),
		"Verifier":  string(d.identity.Address()),
		"StatusURL": strings.TrimSuffix(d.opts.PublicBaseURL, "/") + "/status/" + rec.Token,
	}
	for k, v := range extra {
		data[k] = v
	}
	var b strings.Builder
	_ = tpl.Execute(&b, data)
	return mailer.Message{
		To:      rec.Email,
		ToName:  name,
		Subject: subject,
		Text:    b.String(),
	}
}

// send delivers a message and records the outcome on the case. The
// error is returned so the caller can decide whether it matters: for
// the opening link it does — a customer who never receives it cannot
// complete a check we have already paid for — while for the closing
// notices it does not.
func (d *Verifications) send(ctx context.Context, rec *models.Verification, msg mailer.Message) error {
	sendCtx, cancel := context.WithTimeout(ctx, deliveryTimeout)
	defer cancel()
	now := time.Now().UTC()
	rec.EmailAttempts++
	if err := d.mailer.Send(sendCtx, msg); err != nil {
		rec.LastEmailError = err.Error()
		d.log.Warn("email.send_failed", "address", string(rec.Address), "to", rec.Email, "error", err.Error())
		if perr := d.store.Put(ctx, rec); perr != nil {
			d.log.Error("email.persist_failed", "address", string(rec.Address), "error", perr.Error())
		}
		return err
	}
	rec.EmailSentAt = &now
	rec.LastEmailError = ""
	d.log.Info("email.sent", "address", string(rec.Address), "to", rec.Email)
	// The email is out: a bookkeeping failure here must not fail the
	// request and trigger a duplicate send.
	if err := d.store.Put(ctx, rec); err != nil {
		d.log.Error("email.persist_failed", "address", string(rec.Address), "error", err.Error())
	}
	return nil
}

// partyName returns the stored party's name, for the greeting.
func partyName(rec *models.Verification) string {
	if rec.Facts.LegalName != "" {
		return rec.Facts.LegalName
	}
	if rec.Envelope != nil {
		if party, ok := rec.Envelope.Extract().(*org.Party); ok && party != nil {
			return party.Name
		}
	}
	return ""
}
