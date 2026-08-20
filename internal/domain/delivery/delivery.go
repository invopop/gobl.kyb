// Package delivery POSTs a signed envelope to a remote GOBL Net
// inbox (e.g. the sender's own /.well-known/gobl/inbox) after the
// lookup has countersigned it. The transport reuses gobl/net's
// rules: HTTPS only, refuse to dial loopback / private / link-local
// / multicast / unspecified addresses (SSRF defense). The check is
// inlined here rather than imported from gobl/net (the helpers are
// unexported there); the canonical implementation lives in
// gobl/net/client.go.
package delivery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	stdnet "net"
	"net/http"
	"time"

	"github.com/invopop/gobl"
	"github.com/invopop/gobl/dsig"
	"github.com/invopop/gobl/net"
)

// dialTimeout bounds connection establishment (dial + TLS handshake).
// The overall request deadline is governed by the caller's context, not
// a fixed http.Client.Timeout, so it stays consistent with the domain's
// delivery timeout.
const dialTimeout = 5 * time.Second

// Errors returned by Send.
var (
	// ErrInboxRejected matches gobl/net's sentinel — the remote
	// /inbox definitively rejected the envelope (a non-429 4xx);
	// retrying will not help.
	ErrInboxRejected = net.ErrInboxRejected
	// ErrUnavailable matches gobl/net's sentinel — the remote /inbox
	// could not be reached or answered 429/5xx; the delivery should
	// be retried.
	ErrUnavailable = net.ErrUnavailable
	// ErrSendFailed wraps input / encoding errors during send.
	ErrSendFailed = errors.New("delivery: send failed")
)

// Sender posts a countersigned envelope to a remote GOBL Net inbox.
// The domain depends on this interface; HTTPSender is the production
// implementation and tests substitute their own.
type Sender interface {
	Send(ctx context.Context, addr net.Address, env *gobl.Envelope) error
}

// HTTPSender is the HTTP implementation of Sender. Construct with New;
// the zero value is not usable. Every request carries a bearer
// request token (spec §5.5) minted from this service's own identity.
type HTTPSender struct {
	client *http.Client
	self   net.Address
	key    *dsig.PrivateKey
}

// New returns an HTTPSender whose transport refuses to dial any
// resolved IP that is loopback, private, link-local, multicast, or
// unspecified, and which authenticates its requests as self.
func New(self net.Address, key *dsig.PrivateKey) *HTTPSender {
	return newSender(self, key, false)
}

// newSender builds an HTTPSender; allowLoopback bypasses the SSRF
// guard, intended only for tests that talk to httptest servers bound
// to 127.0.0.1. There is no public wrapper that exposes it.
func newSender(self net.Address, key *dsig.PrivateKey, allowLoopback bool) *HTTPSender {
	transport := &http.Transport{
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          50,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   dialTimeout,
		ExpectContinueTimeout: 1 * time.Second,
	}
	if !allowLoopback {
		transport.DialContext = safeDialContext
	}
	return &HTTPSender{
		// No fixed Timeout: the per-request deadline comes from the
		// caller's context (see Send), keeping it in step with the
		// domain's delivery timeout.
		client: &http.Client{Transport: transport},
		self:   self,
		key:    key,
	}
}

// Send posts env to the remote address's /inbox URL. The host
// (derived from net.Address.InboxURL) MUST resolve to a public IP
// (see SSRF defense above).
func (s *HTTPSender) Send(ctx context.Context, addr net.Address, env *gobl.Envelope) error {
	if env == nil {
		return fmt.Errorf("%w: envelope is nil", ErrSendFailed)
	}
	if err := addr.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrSendFailed, err)
	}
	body, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("%w: marshal envelope: %v", ErrSendFailed, err)
	}
	url := addr.InboxURL()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%w: build request: %v", ErrSendFailed, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	token, err := net.NewToken(s.key, s.self, addr, 0)
	if err != nil {
		return fmt.Errorf("%w: mint request token: %v", ErrSendFailed, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := s.client.Do(req)
	if err != nil {
		// Transport failures are transient: the async delivery loop
		// retries them, unlike definitive inbox rejections.
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	switch {
	case resp.StatusCode == http.StatusAccepted:
		return nil
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return fmt.Errorf("%w: HTTP %d from %s", ErrUnavailable, resp.StatusCode, url)
	default:
		return fmt.Errorf("%w: HTTP %d from %s", ErrInboxRejected, resp.StatusCode, url)
	}
}

// safeDialContext is the DialContext used by the default HTTPSender's
// transport. Duplicates gobl/net/client.go's logic — see the package
// doc for why.
func safeDialContext(ctx context.Context, network, addr string) (stdnet.Conn, error) {
	host, port, err := stdnet.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := stdnet.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSendFailed, err)
	}
	for _, ip := range ips {
		if !isPublicIP(ip) {
			return nil, fmt.Errorf("%w: refusing to dial non-public address %s (%s)", ErrSendFailed, host, ip)
		}
	}
	// Dial the IPs we just vetted rather than re-resolving the host at
	// connect time: a second resolution could return a different, private
	// address and slip past the check (DNS rebinding / TOCTOU).
	d := &stdnet.Dialer{Timeout: dialTimeout}
	var lastErr error
	for _, ip := range ips {
		conn, err := d.DialContext(ctx, network, stdnet.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("%w: no addresses for %s", ErrSendFailed, host)
	}
	return nil, lastErr
}

// isPublicIP rejects any loopback, private (RFC 1918 / RFC 6598),
// link-local, multicast, or unspecified IP. Mirrors the helper in
// gobl/net/client.go.
func isPublicIP(ip stdnet.IP) bool {
	if ip == nil {
		return false
	}
	switch {
	case ip.IsLoopback(),
		ip.IsPrivate(),
		ip.IsLinkLocalUnicast(),
		ip.IsLinkLocalMulticast(),
		ip.IsInterfaceLocalMulticast(),
		ip.IsUnspecified(),
		ip.IsMulticast():
		return false
	}
	return true
}
