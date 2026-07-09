// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gonewx/wicket/accessor"
	"github.com/gonewx/wicket/auth"
	"github.com/gonewx/wicket/claims"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/services"
	sessionpkg "github.com/gonewx/wicket/session"
	gois "github.com/gonewx/wicket"
)

type sessionStateClock struct{ now time.Time }

func (c *sessionStateClock) Now() time.Time { return c.now }

func newSessionStateClock() *sessionStateClock {
	return &sessionStateClock{now: time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)}
}

// recordingAccessor implements both HttpContextAccessor and
// HttpResponseWriterAccessor so UserSession cookie helpers can read the request
// and write to the response, mirroring the request-scope wiring in hosting.
type recordingAccessor struct {
	req *http.Request
	rw  http.ResponseWriter
}

func (a *recordingAccessor) Request() *http.Request               { return a.req }
func (a *recordingAccessor) SetRequest(r *http.Request)           { a.req = r }
func (a *recordingAccessor) ResponseWriter() http.ResponseWriter  { return a.rw }
func (a *recordingAccessor) SetResponseWriter(w http.ResponseWriter) { a.rw = w }

func principalWithSubject(sub string) *claims.ClaimsPrincipal {
	id := claims.NewClaimsIdentity(
		claims.WithAuthenticationType("test"),
		claims.WithClaims([]*claims.Claim{
			claims.NewClaim(
				claims.WithClaimType(gois.JwtClaimTypesSubject),
				claims.WithClaimValue(sub),
			),
		}),
	)
	return claims.NewClaimsPrincipal(claims.WithClaimsPrincipalIdentity(id))
}

func newSessionUserSession(t *testing.T, enabled bool, store sessionpkg.Store, acc accessor.HttpContextAccessor, clock services.SystemClock) *UserSession {
	t.Helper()
	opts := &config_options.WicketOptions{
		ServerSideSessions: &config_options.ServerSideSessionOptions{
			Enabled:         enabled,
			SessionLifetime: 24 * time.Hour,
			CookieName:      "wicket.session",
		},
	}
	return NewUserSession(acc, nil, opts, clock, nil, nil, nil, store)
}

// TestUserSessionDisabledTwoState verifies that with server-side sessions
// disabled the UserSession keeps its in-memory-only behavior: nothing is
// written to the store and no session cookie is emitted.
func TestUserSessionDisabledTwoState(t *testing.T) {
	t.Parallel()

	clock := newSessionStateClock()
	store := sessionpkg.NewMemoryStore(clock)
	rec := httptest.NewRecorder()
	acc := &recordingAccessor{req: httptest.NewRequest(http.MethodGet, "/", nil), rw: rec}

	us := newSessionUserSession(t, false, store, acc, clock)

	sid, err := us.CreateSessionId(principalWithSubject("alice"), &auth.Properties{})
	if err != nil {
		t.Fatalf("CreateSessionId: %v", err)
	}
	if sid == "" {
		t.Fatal("expected non-empty session id")
	}
	if got, _ := store.GetSession(sid); got != nil {
		t.Fatal("disabled UserSession must not write to the store")
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Fatal("disabled UserSession must not set a session cookie")
	}

	if err := us.EnsureSessionIdCookie(); err != nil {
		t.Fatalf("EnsureSessionIdCookie: %v", err)
	}
}

// TestUserSessionEnabledCreatePersistsAndSetsCookie verifies the enabled-state
// CreateSessionId path: a record lands in the store and a session cookie is
// written to the response.
func TestUserSessionEnabledCreatePersistsAndSetsCookie(t *testing.T) {
	t.Parallel()

	clock := newSessionStateClock()
	store := sessionpkg.NewMemoryStore(clock)
	rec := httptest.NewRecorder()
	acc := &recordingAccessor{req: httptest.NewRequest(http.MethodGet, "/", nil), rw: rec}

	us := newSessionUserSession(t, true, store, acc, clock)

	sid, err := us.CreateSessionId(principalWithSubject("alice"), &auth.Properties{})
	if err != nil {
		t.Fatalf("CreateSessionId: %v", err)
	}

	stored, err := store.GetSession(sid)
	if err != nil || stored == nil {
		t.Fatalf("session not persisted: got=%v err=%v", stored, err)
	}
	if stored.SubjectID != "alice" {
		t.Fatalf("SubjectID = %q, want alice", stored.SubjectID)
	}
	if !stored.Expires.Equal(clock.Now().Add(24 * time.Hour)) {
		t.Fatalf("Expires = %v, want creation + lifetime", stored.Expires)
	}

	var sessionCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "wicket.session" {
			sessionCookie = c
		}
	}
	if sessionCookie == nil {
		t.Fatal("expected session cookie to be set")
	}
	if sessionCookie.Value != sid {
		t.Fatalf("cookie value = %q, want session id %q", sessionCookie.Value, sid)
	}
	if !sessionCookie.HttpOnly {
		t.Fatal("session cookie should be HttpOnly")
	}
}

// TestUserSessionEnabledEnsureLoadsFromCookie verifies the enabled-state
// EnsureSessionIdCookie path: a fresh UserSession restores its internal state
// (session id, client list) from a session referenced by the request cookie,
// which is the cross-request recovery contract.
func TestUserSessionEnabledEnsureLoadsFromCookie(t *testing.T) {
	t.Parallel()

	clock := newSessionStateClock()
	store := sessionpkg.NewMemoryStore(clock)

	seed := &sessionpkg.Record{
		SessionID: "seed-session",
		SubjectID: "alice",
		Created:   clock.Now(),
		Renewed:   clock.Now(),
		Expires:   clock.Now().Add(24 * time.Hour),
		ClientIDs: []string{"client-a"},
	}
	if err := store.CreateSession(seed); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "wicket.session", Value: "seed-session"})
	acc := &recordingAccessor{req: req, rw: httptest.NewRecorder()}

	us := newSessionUserSession(t, true, store, acc, clock)

	if err := us.EnsureSessionIdCookie(); err != nil {
		t.Fatalf("EnsureSessionIdCookie: %v", err)
	}
	if us.GetSessionId() != "seed-session" {
		t.Fatalf("GetSessionId = %q, want seed-session", us.GetSessionId())
	}
	list, _ := us.GetClientList()
	if len(list) != 1 || list[0] != "client-a" {
		t.Fatalf("GetClientList = %v, want [client-a] loaded from store", list)
	}
}

// TestUserSessionEnabledEnsureClearsStaleCookie verifies graceful degradation:
// a cookie referencing a missing session clears the cookie and leaves internal
// state empty without erroring.
func TestUserSessionEnabledEnsureClearsStaleCookie(t *testing.T) {
	t.Parallel()

	clock := newSessionStateClock()
	store := sessionpkg.NewMemoryStore(clock)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "wicket.session", Value: "gone"})
	rec := httptest.NewRecorder()
	acc := &recordingAccessor{req: req, rw: rec}

	us := newSessionUserSession(t, true, store, acc, clock)

	if err := us.EnsureSessionIdCookie(); err != nil {
		t.Fatalf("EnsureSessionIdCookie: %v", err)
	}
	if us.GetSessionId() != "" {
		t.Fatalf("GetSessionId = %q, want empty for stale cookie", us.GetSessionId())
	}

	var cleared bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == "wicket.session" && c.MaxAge < 0 || (c.Name == "wicket.session" && !c.Expires.IsZero() && c.Expires.Before(clock.Now())) {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("expected stale session cookie to be cleared")
	}
}

// TestUserSessionEnabledAddClientPersists verifies AddClientId writes through to
// the store atomically (via the store's AddClientID) in the enabled state.
func TestUserSessionEnabledAddClientPersists(t *testing.T) {
	t.Parallel()

	clock := newSessionStateClock()
	store := sessionpkg.NewMemoryStore(clock)
	rec := httptest.NewRecorder()
	acc := &recordingAccessor{req: httptest.NewRequest(http.MethodGet, "/", nil), rw: rec}

	us := newSessionUserSession(t, true, store, acc, clock)

	sid, err := us.CreateSessionId(principalWithSubject("alice"), &auth.Properties{})
	if err != nil {
		t.Fatal(err)
	}
	if err := us.AddClientId("client-x"); err != nil {
		t.Fatalf("AddClientId: %v", err)
	}

	stored, _ := store.GetSession(sid)
	if stored == nil {
		t.Fatal("session missing")
	}
	found := false
	for _, c := range stored.ClientIDs {
		if c == "client-x" {
			found = true
		}
	}
	if !found {
		t.Fatalf("store client list %v missing client-x", stored.ClientIDs)
	}
}

// TestUserSessionRemoveClearsCookieNotRecord verifies RemoveSessionIdCookie
// clears cookie + internal state but leaves the server-side record intact (the
// specification assigns record deletion to the coordinator/management surface,
// not the cookie concern).
func TestUserSessionRemoveClearsCookieNotRecord(t *testing.T) {
	t.Parallel()

	clock := newSessionStateClock()
	store := sessionpkg.NewMemoryStore(clock)
	rec := httptest.NewRecorder()
	acc := &recordingAccessor{req: httptest.NewRequest(http.MethodGet, "/", nil), rw: rec}

	us := newSessionUserSession(t, true, store, acc, clock)
	sid, err := us.CreateSessionId(principalWithSubject("alice"), &auth.Properties{})
	if err != nil {
		t.Fatal(err)
	}

	if err := us.RemoveSessionIdCookie(); err != nil {
		t.Fatalf("RemoveSessionIdCookie: %v", err)
	}
	if us.GetSessionId() != "" {
		t.Fatal("internal session id should be cleared")
	}
	if got, _ := store.GetSession(sid); got == nil {
		t.Fatal("server-side record must survive cookie removal")
	}
}

// TestSessionCoordinationAdapterValidatePath exercises the exact call shape the
// token validator uses: ValidateSession(*SessionValidationRequest) routed
// through the adapter to the coordinator, covering the disabled pass-through
// and the enabled valid/missing outcomes keyed on SessionValidationRequest.SessionId.
func TestSessionCoordinationAdapterValidatePath(t *testing.T) {
	t.Parallel()

	clock := newSessionStateClock()

	t.Run("disabled pass-through", func(t *testing.T) {
		t.Parallel()
		store := sessionpkg.NewMemoryStore(clock)
		adapter := NewSessionCoordinationAdapter(sessionpkg.NewCoordinator(store, clock, false))
		valid, err := adapter.ValidateSession(&services.SessionValidationRequest{
			Type:      services.SessionValidationTypeAccessToken,
			SubjectId: "alice",
			SessionId: "anything",
		})
		if err != nil || !valid {
			t.Fatalf("disabled: got valid=%v err=%v, want true/nil", valid, err)
		}
	})

	t.Run("enabled valid session", func(t *testing.T) {
		t.Parallel()
		store := sessionpkg.NewMemoryStore(clock)
		if err := store.CreateSession(&sessionpkg.Record{
			SessionID: "sid-1",
			SubjectID: "alice",
			Created:   clock.Now(),
			Renewed:   clock.Now(),
			Expires:   clock.Now().Add(time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
		adapter := NewSessionCoordinationAdapter(sessionpkg.NewCoordinator(store, clock, true))
		valid, err := adapter.ValidateSession(&services.SessionValidationRequest{
			Type:      services.SessionValidationTypeAccessToken,
			SubjectId: "alice",
			SessionId: "sid-1",
		})
		if err != nil || !valid {
			t.Fatalf("enabled valid: got valid=%v err=%v, want true/nil", valid, err)
		}
	})

	t.Run("enabled missing session rejected", func(t *testing.T) {
		t.Parallel()
		store := sessionpkg.NewMemoryStore(clock)
		adapter := NewSessionCoordinationAdapter(sessionpkg.NewCoordinator(store, clock, true))
		valid, err := adapter.ValidateSession(&services.SessionValidationRequest{
			Type:      services.SessionValidationTypeAccessToken,
			SubjectId: "alice",
			SessionId: "unknown",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if valid {
			t.Fatal("enabled missing session should be rejected (false)")
		}
	})
}
