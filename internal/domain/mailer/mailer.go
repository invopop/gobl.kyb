// Package mailer sends the verification emails. The domain depends on
// the Mailer interface declared here; SMTP is the production transport
// (provider-agnostic — any submission service speaks it) and LogMailer
// is the development fallback when no SMTP host is configured.
package mailer

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// Message is a plain-text email. The domain builds the content; the
// mailer only transports it.
type Message struct {
	// To is the destination email address (addr-spec only).
	To string
	// ToName is an optional display name for the destination.
	ToName string
	// Subject line.
	Subject string
	// Text is the plain-text body.
	Text string
}

// Mailer delivers a message. Implementations must honour the context
// deadline.
type Mailer interface {
	Send(ctx context.Context, msg Message) error
}

// SMTP submits messages over SMTP with PLAIN authentication and
// opportunistic STARTTLS (negotiated whenever the server offers it,
// as every hosted submission endpoint does).
type SMTP struct {
	host     string
	port     int
	username string
	password string
	from     string
}

// NewSMTP configures an SMTP mailer. Empty username skips
// authentication (a local relay). The from address is used both as
// the envelope sender and the From header.
func NewSMTP(host string, port int, username, password, from string) *SMTP {
	return &SMTP{host: host, port: port, username: username, password: password, from: from}
}

// Send submits the message. The context deadline bounds the whole
// exchange: net/smtp has no context support, so the deadline is
// applied to the underlying connection.
func (s *SMTP) Send(ctx context.Context, msg Message) error {
	if msg.To == "" {
		return errors.New("mailer: message has no destination")
	}
	addr := net.JoinHostPort(s.host, strconv.Itoa(s.port))
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(30 * time.Second)
	}
	conn, err := (&net.Dialer{Deadline: deadline}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("mailer: dial %s: %w", addr, err)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		conn.Close() //nolint:errcheck
		return fmt.Errorf("mailer: set deadline: %w", err)
	}
	c, err := smtp.NewClient(conn, s.host)
	if err != nil {
		conn.Close() //nolint:errcheck
		return fmt.Errorf("mailer: smtp handshake: %w", err)
	}
	defer c.Close() //nolint:errcheck
	if ok, _ := c.Extension("STARTTLS"); ok {
		// The config needs the server name for certificate verification;
		// a nil config is rejected by crypto/tls outright.
		tlsConf := &tls.Config{ServerName: s.host, MinVersion: tls.VersionTLS12}
		if err := c.StartTLS(tlsConf); err != nil {
			return fmt.Errorf("mailer: starttls: %w", err)
		}
	}
	if s.username != "" {
		if err := c.Auth(smtp.PlainAuth("", s.username, s.password, s.host)); err != nil {
			return fmt.Errorf("mailer: auth: %w", err)
		}
	}
	if err := c.Mail(envelopeAddr(s.from)); err != nil {
		return fmt.Errorf("mailer: mail from: %w", err)
	}
	if err := c.Rcpt(msg.To); err != nil {
		return fmt.Errorf("mailer: rcpt to: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("mailer: data: %w", err)
	}
	if _, err := w.Write(render(s.from, msg)); err != nil {
		return fmt.Errorf("mailer: write body: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("mailer: close body: %w", err)
	}
	return c.Quit()
}

// render assembles the RFC 5322 message bytes.
func render(from string, msg Message) []byte {
	var b strings.Builder
	to := msg.To
	if msg.ToName != "" {
		to = mime.QEncoding.Encode("utf-8", msg.ToName) + " <" + msg.To + ">"
	}
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + to + "\r\n")
	b.WriteString("Subject: " + mime.QEncoding.Encode("utf-8", msg.Subject) + "\r\n")
	b.WriteString("Date: " + time.Now().UTC().Format(time.RFC1123Z) + "\r\n")
	b.WriteString("Message-ID: <" + messageID(from) + ">\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("\r\n")
	// Dot-stuffing is handled by smtp's Data writer; normalise bare
	// newlines to CRLF.
	b.WriteString(strings.ReplaceAll(strings.ReplaceAll(msg.Text, "\r\n", "\n"), "\n", "\r\n"))
	return []byte(b.String())
}

// messageID builds a random Message-ID using the sender's domain.
func messageID(from string) string {
	var r [12]byte
	_, _ = rand.Read(r[:])
	domain := envelopeAddr(from)
	if i := strings.LastIndex(domain, "@"); i >= 0 {
		domain = domain[i+1:]
	}
	return hex.EncodeToString(r[:]) + "@" + domain
}

// envelopeAddr extracts the addr-spec from a From value that may carry
// a display name ("Name <a@b>" → "a@b").
func envelopeAddr(from string) string {
	if i := strings.LastIndex(from, "<"); i >= 0 {
		if j := strings.LastIndex(from, ">"); j > i {
			return from[i+1 : j]
		}
	}
	return strings.TrimSpace(from)
}

// LogMailer is the development fallback used when no SMTP host is
// configured: it logs each message — including the verification link —
// instead of sending it. That is all a local loop needs.
type LogMailer struct {
	log *slog.Logger
}

// NewLogMailer wraps a logger as a Mailer.
func NewLogMailer(log *slog.Logger) *LogMailer {
	return &LogMailer{log: log}
}

// Send logs the message.
func (m *LogMailer) Send(_ context.Context, msg Message) error {
	m.log.Info("mailer.logged",
		"to", msg.To,
		"subject", msg.Subject,
		"text", msg.Text,
	)
	return nil
}
