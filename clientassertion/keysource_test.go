// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package clientassertion

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// jwksServer is a TLS server that publishes a JWK Set and counts requests.
type jwksServer struct {
	server   *httptest.Server
	requests atomic.Int64
	mu       sync.Mutex
	status   int
	body     string
	location string
	delay    time.Duration
}

func newJwksServer(t *testing.T, body string) *jwksServer {
	t.Helper()
	s := &jwksServer{status: http.StatusOK, body: body}
	s.server = httptest.NewTLSServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.server.Close)
	return s
}

func (s *jwksServer) serve(w http.ResponseWriter, _ *http.Request) {
	s.requests.Add(1)
	s.mu.Lock()
	status, body, location, delay := s.status, s.body, s.location, s.delay
	s.mu.Unlock()
	if delay > 0 {
		time.Sleep(delay)
	}
	if location != "" {
		w.Header().Set("Location", location)
	}
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func (s *jwksServer) publish(status int, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status, s.body = status, body
}

func (s *jwksServer) address() string { return s.server.URL + "/jwks" }

func (s *jwksServer) options() Options { return Options{HTTPClient: s.server.Client()} }

func (s *jwksServer) count() int64 { return s.requests.Load() }

func TestKeySourceFetchesOnceAndCaches(t *testing.T) {
	key := keyFor(t, "ES256", "a")
	server := newJwksServer(t, keySet(t, key))
	f := newFixture(server.options())
	principal := Principal{ID: "client", JwksUri: server.address()}
	for i := 0; i < 3; i++ {
		if err := f.verify(principal, key.sign(t, "ES256", f.claims("client"))); err != nil {
			t.Fatalf("Verify %d: %v", i, err)
		}
	}
	if got := server.count(); got != 1 {
		t.Fatalf("server saw %d requests, want 1", got)
	}
}

func TestKeySourceRefreshesOnceForAnUnknownKeyId(t *testing.T) {
	first := keyFor(t, "ES256", "a")
	second := keyFor(t, "ES256", "b")
	third := keyFor(t, "ES256", "c")
	server := newJwksServer(t, keySet(t, first))
	f := newFixture(server.options())
	principal := Principal{ID: "client", JwksUri: server.address()}

	if err := f.verify(principal, first.sign(t, "ES256", f.claims("client"))); err != nil {
		t.Fatalf("first key: %v", err)
	}
	server.publish(http.StatusOK, keySet(t, second))
	f.clock.advance(61 * time.Second)
	if err := f.verify(principal, second.sign(t, "ES256", f.claims("client"))); err != nil {
		t.Fatalf("rotated key: %v", err)
	}
	if got := server.count(); got != 2 {
		t.Fatalf("server saw %d requests after rotation, want 2", got)
	}

	// Still unknown, and inside the minimum refresh interval: no request.
	for i := 0; i < 5; i++ {
		if err := f.verify(principal, third.sign(t, "ES256", f.claims("client"))); err == nil {
			t.Fatalf("unknown key accepted")
		}
	}
	if got := server.count(); got != 2 {
		t.Fatalf("server saw %d requests, want the count to stay at 2", got)
	}
	if f.registry.callCount() != 2 {
		t.Fatalf("registry called %d times, want 2", f.registry.callCount())
	}

	// Past the interval one more refresh is allowed, once.
	f.clock.advance(61 * time.Second)
	if err := f.verify(principal, third.sign(t, "ES256", f.claims("client"))); err == nil {
		t.Fatalf("unknown key accepted")
	}
	if got := server.count(); got != 3 {
		t.Fatalf("server saw %d requests, want 3", got)
	}
}

func TestKeySourceDoesNotRefreshWithoutAKeyId(t *testing.T) {
	first := keyFor(t, "ES256", "a")
	other := testKey{private: keyFor(t, "ES256", "").private}
	server := newJwksServer(t, keySet(t, first))
	f := newFixture(server.options())
	principal := Principal{ID: "client", JwksUri: server.address()}
	if err := f.verify(principal, first.sign(t, "ES256", f.claims("client"))); err != nil {
		t.Fatalf("first key: %v", err)
	}
	f.clock.advance(61 * time.Second)
	if err := f.verify(principal, other.sign(t, "ES256", f.claims("client"))); err == nil {
		t.Fatalf("foreign signature accepted")
	}
	if got := server.count(); got != 1 {
		t.Fatalf("server saw %d requests, want 1", got)
	}
}

func TestKeySourceFetchFailures(t *testing.T) {
	key := keyFor(t, "ES256", "a")
	valid := keySet(t, key)
	redirectTarget := newJwksServer(t, valid)

	cases := []struct {
		name    string
		prepare func(s *jwksServer, o *Options)
	}{
		{"server error", func(s *jwksServer, _ *Options) { s.status = http.StatusInternalServerError }},
		{"not found", func(s *jwksServer, _ *Options) { s.status = http.StatusNotFound }},
		{"redirect", func(s *jwksServer, _ *Options) {
			s.status = http.StatusFound
			s.location = redirectTarget.address()
		}},
		{"oversized response", func(s *jwksServer, o *Options) {
			s.body = valid + strings.Repeat(" ", 4096)
			o.MaxJwksResponseBytes = 2048
		}},
		{"invalid JSON", func(s *jwksServer, _ *Options) { s.body = "{not json" }},
		{"empty key set", func(s *jwksServer, _ *Options) { s.body = `{"keys":[]}` }},
		{"timeout", func(s *jwksServer, o *Options) {
			s.delay = 300 * time.Millisecond
			o.JwksFetchTimeout = 20 * time.Millisecond
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := newJwksServer(t, valid)
			options := server.options()
			tc.prepare(server, &options)
			f := newFixture(options)
			principal := Principal{ID: "client", JwksUri: server.address()}
			mustReject(t, f, f.verify(principal, key.sign(t, "ES256", f.claims("client"))))
			if got := server.count(); got != 1 {
				t.Fatalf("server saw %d requests, want 1", got)
			}
		})
	}
	if got := redirectTarget.count(); got != 0 {
		t.Fatalf("redirect was followed: %d requests", got)
	}
}

func TestKeySourceLimitsRequestsToAnUnreachableAddress(t *testing.T) {
	key := keyFor(t, "ES256", "a")
	server := newJwksServer(t, "")
	server.publish(http.StatusServiceUnavailable, "")
	f := newFixture(server.options())
	principal := Principal{ID: "client", JwksUri: server.address()}
	for i := 0; i < 20; i++ {
		if err := f.verify(principal, key.sign(t, "ES256", f.claims("client"))); err == nil {
			t.Fatalf("accepted without keys")
		}
	}
	if got := server.count(); got != 1 {
		t.Fatalf("server saw %d requests, want 1", got)
	}
	if f.registry.callCount() != 0 {
		t.Fatalf("registry called %d times, want 0", f.registry.callCount())
	}
}

func TestKeySourceKeepsItsKeysWhenARefreshFails(t *testing.T) {
	key := keyFor(t, "ES256", "a")
	unknown := keyFor(t, "ES256", "b")
	server := newJwksServer(t, keySet(t, key))
	f := newFixture(server.options())
	principal := Principal{ID: "client", JwksUri: server.address()}
	if err := f.verify(principal, key.sign(t, "ES256", f.claims("client"))); err != nil {
		t.Fatalf("first use: %v", err)
	}
	server.publish(http.StatusInternalServerError, "")
	f.clock.advance(61 * time.Second)
	if err := f.verify(principal, unknown.sign(t, "ES256", f.claims("client"))); err == nil {
		t.Fatalf("unknown key accepted")
	}
	if got := server.count(); got != 2 {
		t.Fatalf("server saw %d requests, want 2", got)
	}
	if err := f.verify(principal, key.sign(t, "ES256", f.claims("client"))); err != nil {
		t.Fatalf("known key after a failed refresh: %v", err)
	}
	if got := server.count(); got != 2 {
		t.Fatalf("server saw %d requests, want 2", got)
	}
}

func TestKeySourceDropsExpiredKeysWhenTheReloadFails(t *testing.T) {
	key := keyFor(t, "ES256", "a")
	server := newJwksServer(t, keySet(t, key))
	options := server.options()
	options.JwksCacheLifetime = 10 * time.Minute
	f := newFixture(options)
	principal := Principal{ID: "client", JwksUri: server.address()}
	if err := f.verify(principal, key.sign(t, "ES256", f.claims("client"))); err != nil {
		t.Fatalf("first use: %v", err)
	}
	server.publish(http.StatusInternalServerError, "")
	f.clock.advance(11 * time.Minute)
	if err := f.verify(principal, key.sign(t, "ES256", f.claims("client"))); err == nil {
		t.Fatalf("expired key set still used after a failed reload")
	}
	if got := server.count(); got != 2 {
		t.Fatalf("server saw %d requests, want 2", got)
	}
}

func TestKeySourceSharesOneFetchAmongConcurrentCallers(t *testing.T) {
	key := keyFor(t, "ES256", "a")
	server := newJwksServer(t, keySet(t, key))
	server.delay = 50 * time.Millisecond
	f := newFixture(server.options())
	principal := Principal{ID: "client", JwksUri: server.address()}

	const callers = 32
	assertions := make([]string, callers)
	for i := range assertions {
		assertions[i] = key.sign(t, "ES256", f.claims("client"))
	}
	errs := make([]error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = f.verify(principal, assertions[i])
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("caller %d: %v", i, err)
		}
	}
	if got := server.count(); got != 1 {
		t.Fatalf("server saw %d requests, want 1", got)
	}
}

func TestKeySourceRejectsAnInsecureAddressWithoutARequest(t *testing.T) {
	key := keyFor(t, "ES256", "a")
	var requests atomic.Int64
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte(keySet(t, key)))
	}))
	t.Cleanup(plain.Close)

	f := newFixture(Options{})
	principal := Principal{ID: "client", JwksUri: plain.URL + "/jwks"}
	mustReject(t, f, f.verify(principal, key.sign(t, "ES256", f.claims("client"))))
	if got := requests.Load(); got != 0 {
		t.Fatalf("insecure address was requested %d times", got)
	}

	for _, address := range []string{"ftp://client.example/jwks", "https:///jwks", "://bad", "/relative"} {
		g := newFixture(Options{AllowInsecureJwksUri: true})
		mustReject(t, g, g.verify(Principal{ID: "client", JwksUri: address}, key.sign(t, "ES256", g.claims("client"))))
	}

	allowed := newFixture(Options{AllowInsecureJwksUri: true})
	if err := allowed.verify(principal, key.sign(t, "ES256", allowed.claims("client"))); err != nil {
		t.Fatalf("insecure address with the opt-in: %v", err)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("server saw %d requests, want 1", got)
	}
}

func TestVerifyIgnoresKeysNamedInTheHeader(t *testing.T) {
	registered := keyFor(t, "ES256", "a")
	intruder := keyFor(t, "ES256", "a")
	elsewhere := newJwksServer(t, keySet(t, intruder))

	f := newFixture(elsewhere.options())
	principal := Principal{ID: "client", Jwks: keySet(t, registered)}
	header := map[string]any{
		"jku": elsewhere.address(),
		"jwk": intruder.jwk(t),
		"x5u": elsewhere.address(),
	}
	mustReject(t, f, f.verify(principal, intruder.signAs(t, "ES256", "ES256", header, f.claims("client"))))
	if got := elsewhere.count(); got != 0 {
		t.Fatalf("address named in the header was requested %d times", got)
	}

	// The same header members do not disturb a properly signed assertion.
	g := newFixture(elsewhere.options())
	if err := g.verify(principal, registered.signAs(t, "ES256", "ES256", header, g.claims("client"))); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got := elsewhere.count(); got != 0 {
		t.Fatalf("address named in the header was requested %d times", got)
	}
}
