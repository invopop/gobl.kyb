// Package mock is an in-process KYB provider for tests and local
// development.
//
// It exists for a specific reason. Every real provider bills per
// check, so a service whose whole job is to run them cannot have its
// state machine exercised only against the real thing: the tests that
// matter most — the ones about re-submission, session re-use and the
// cost ceiling — are exactly the ones that would cost money to run.
// This implementation lets the entire choreography be driven, in CI
// and on a laptop, without spending anything.
package mock

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/invopop/gobl.kyb/internal/domain/provider"
)

// Name identifies this provider.
const Name provider.Name = "mock"

// Provider is a scriptable KYB provider.
type Provider struct {
	mu sync.Mutex

	// seq numbers the sessions it hands out.
	seq int
	// sessions records what was created, keyed by session id.
	sessions map[string]provider.SessionRequest
	// decisions is what Decision returns per session id.
	decisions map[string]*provider.Decision
	// events is the queue ParseEvent drains, oldest first.
	events []*provider.Event

	// CreateErr, when set, fails the next CreateSession — the path
	// that must never be retried automatically.
	CreateErr error
	// DecisionErr, when set, fails Decision.
	DecisionErr error
	// Default is returned by Decision for sessions with no scripted
	// verdict.
	Default provider.Decision
}

// New returns a mock provider whose sessions stay pending until a
// decision is scripted.
func New() *Provider {
	return &Provider{
		sessions:  make(map[string]provider.SessionRequest),
		decisions: make(map[string]*provider.Decision),
		Default:   provider.Decision{Status: provider.StatusPending},
	}
}

// Name identifies the implementation.
func (p *Provider) Name() provider.Name { return Name }

// CreateSession records the request and hands back a session.
func (p *Provider) CreateSession(_ context.Context, req provider.SessionRequest) (*provider.Session, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.CreateErr; err != nil {
		p.CreateErr = nil
		return nil, err
	}
	p.seq++
	id := fmt.Sprintf("mock-session-%d", p.seq)
	p.sessions[id] = req
	return &provider.Session{
		ID:     id,
		Number: fmt.Sprintf("%d", p.seq),
		URL:    "https://mock.invalid/verify/" + id,
	}, nil
}

// Decision returns the scripted verdict for a session.
func (p *Provider) Decision(_ context.Context, sessionID string) (*provider.Decision, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.DecisionErr; err != nil {
		return nil, err
	}
	if d, ok := p.decisions[sessionID]; ok {
		clone := *d
		clone.SessionID = sessionID
		return &clone, nil
	}
	clone := p.Default
	clone.SessionID = sessionID
	if clone.Raw == nil {
		clone.Raw = json.RawMessage(`{"mock":true}`)
	}
	return &clone, nil
}

// ParseEvent drains the queued events. Callbacks are pushed with
// Enqueue and the raw body is ignored — the transport is not what
// these tests are about.
func (p *Provider) ParseEvent(_ []byte, _ http.Header, _ time.Time) (*provider.Event, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.events) == 0 {
		return nil, fmt.Errorf("mock: no queued event")
	}
	ev := p.events[0]
	p.events = p.events[1:]
	return ev, nil
}

// Sessions returns how many sessions have been created. With a
// pay-per-check provider this count is money, so it is what the
// re-submission tests assert on.
func (p *Provider) Sessions() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.seq
}

// Request returns the SessionRequest recorded for a session.
func (p *Provider) Request(sessionID string) (provider.SessionRequest, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	req, ok := p.sessions[sessionID]
	return req, ok
}

// SetDecision scripts the verdict for a session.
func (p *Provider) SetDecision(sessionID string, d provider.Decision) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if d.Raw == nil {
		d.Raw = json.RawMessage(`{"mock":true}`)
	}
	if d.DecidedAt.IsZero() {
		d.DecidedAt = time.Now().UTC()
	}
	p.decisions[sessionID] = &d
}

// Enqueue queues a callback for the next ParseEvent.
func (p *Provider) Enqueue(ev provider.Event) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.events = append(p.events, &ev)
}
