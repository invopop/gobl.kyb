package mailer_test

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/invopop/gobl.kyb/internal/domain/mailer"
)

// fakeSMTP is a minimal in-process SMTP server (no TLS) that records
// a single message submission.
type fakeSMTP struct {
	ln       net.Listener
	mu       sync.Mutex
	from     string
	rcpt     []string
	data     string
	authLine string
}

func newFakeSMTP(t *testing.T) *fakeSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	s := &fakeSMTP{ln: ln}
	go s.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *fakeSMTP) hostPort(t *testing.T) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(s.ln.Addr().String())
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	return host, port
}

func (s *fakeSMTP) serve() {
	conn, err := s.ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close() //nolint:errcheck
	w := func(line string) { _, _ = io.WriteString(conn, line+"\r\n") }
	w("220 fake ESMTP")
	r := bufio.NewReader(conn)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			w("250-fake")
			w("250 AUTH PLAIN")
		case strings.HasPrefix(cmd, "AUTH PLAIN"):
			s.mu.Lock()
			s.authLine = strings.TrimSpace(line[len("AUTH PLAIN"):])
			s.mu.Unlock()
			w("235 2.7.0 ok")
		case strings.HasPrefix(cmd, "MAIL FROM:"):
			s.mu.Lock()
			s.from = strings.Trim(strings.TrimSpace(line[len("MAIL FROM:"):]), "<>")
			s.mu.Unlock()
			w("250 ok")
		case strings.HasPrefix(cmd, "RCPT TO:"):
			s.mu.Lock()
			s.rcpt = append(s.rcpt, strings.Trim(strings.TrimSpace(line[len("RCPT TO:"):]), "<>"))
			s.mu.Unlock()
			w("250 ok")
		case cmd == "DATA":
			w("354 go ahead")
			var body strings.Builder
			for {
				dl, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if strings.TrimRight(dl, "\r\n") == "." {
					break
				}
				body.WriteString(dl)
			}
			s.mu.Lock()
			s.data = body.String()
			s.mu.Unlock()
			w("250 accepted")
		case cmd == "QUIT":
			w("221 bye")
			return
		default:
			w("250 ok")
		}
	}
}

func (s *fakeSMTP) snapshot() (from string, rcpt []string, data, auth string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.from, append([]string(nil), s.rcpt...), s.data, s.authLine
}

func TestSMTPSend(t *testing.T) {
	srv := newFakeSMTP(t)
	host, port := srv.hostPort(t)
	m := mailer.NewSMTP(host, port, "mailer", "secret", "GOBL Sandbox KYB <kyb@kyb.example>")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := m.Send(ctx, mailer.Message{
		To:      "alice@example.com",
		ToName:  "Alice",
		Subject: "Verify alice.example",
		Text:    "Open this link:\n\n  https://kyb.example/confirm/tok\n",
	})
	require.NoError(t, err)

	from, rcpt, data, auth := srv.snapshot()
	assert.Equal(t, "kyb@kyb.example", from, "envelope sender is the bare addr-spec")
	assert.Equal(t, []string{"alice@example.com"}, rcpt)
	assert.Contains(t, data, "Subject: Verify alice.example")
	assert.Contains(t, data, "From: GOBL Sandbox KYB <kyb@kyb.example>")
	assert.Contains(t, data, "To: Alice <alice@example.com>")
	assert.Contains(t, data, "https://kyb.example/confirm/tok")
	assert.Contains(t, data, "Message-ID: <")

	// AUTH PLAIN carried the credentials.
	require.NotEmpty(t, auth)
	raw, err := base64.StdEncoding.DecodeString(auth)
	require.NoError(t, err)
	assert.Equal(t, "\x00mailer\x00secret", string(raw))
}

func TestSMTPSendUnauthenticated(t *testing.T) {
	srv := newFakeSMTP(t)
	host, port := srv.hostPort(t)
	m := mailer.NewSMTP(host, port, "", "", "kyb@kyb.example")

	err := m.Send(context.Background(), mailer.Message{
		To:      "alice@example.com",
		Subject: "hi",
		Text:    "body",
	})
	require.NoError(t, err)
	_, _, _, auth := srv.snapshot()
	assert.Empty(t, auth, "no credentials, no AUTH command")
}

func TestSMTPSendRequiresDestination(t *testing.T) {
	m := mailer.NewSMTP("smtp.example", 587, "", "", "kyb@kyb.example")
	err := m.Send(context.Background(), mailer.Message{Subject: "hi"})
	require.Error(t, err)
}

func TestSMTPSendDialFailure(t *testing.T) {
	// A listener that is immediately closed: connection refused.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	require.NoError(t, ln.Close())

	m := mailer.NewSMTP(host, port, "", "", "kyb@kyb.example")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err = m.Send(ctx, mailer.Message{To: "alice@example.com", Subject: "hi", Text: "body"})
	require.Error(t, err)
}

func TestLogMailer(t *testing.T) {
	m := mailer.NewLogMailer(slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, m.Send(context.Background(), mailer.Message{To: "a@b.c", Subject: "s", Text: "t"}))
}
