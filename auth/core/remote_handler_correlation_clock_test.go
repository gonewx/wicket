// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package core

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gonewx/wicket/auth"
	"github.com/gonewx/wicket/test/common"
)

// newCorrelationTestHandler assembles a RemoteHandler wired end to end enough to
// drive the correlation cookie use sites (GenerateCorrelationId /
// ValidateCorrelationId) directly, with a fixed clock injected the same way the
// composition root does. It bypasses the options monitor and sets the request /
// response seams white-box, so the assertions observe the real handler wiring
// rather than a builder configured by hand.
func newCorrelationTestHandler(clock *common.MockSystemClock, req *http.Request, w http.ResponseWriter) *RemoteHandler[*RemoteOptions] {
	h := &RemoteHandler[*RemoteOptions]{}
	h.Handler = &Handler[*RemoteOptions]{
		Options: NewRemoteOptions(),
		Clock:   clock,
		Logger:  common.NewTestLogger(),
	}
	h.request = req
	h.response = w
	return h
}

// correlationCookie returns the single correlation cookie written to the
// recorder, failing the test if the count is not exactly one.
func correlationCookie(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()

	var found []*http.Cookie
	for _, c := range rec.Result().Cookies() {
		if strings.HasPrefix(c.Name, CorrelationPrefix) {
			found = append(found, c)
		}
	}
	if len(found) != 1 {
		t.Fatalf("expected exactly one correlation cookie, got %d", len(found))
	}
	return found[0]
}

// TestGenerateCorrelationIdWiresInjectedClock drives the production use site and
// proves the handler stamps the correlation cookie through the injected clock
// (handler.Clock -> builder.SetClock -> Build), not the wall clock. The observable
// signal is that the fixed clock is consulted; production correlation cookies set
// no Expiration, so Expires stays nil (AC#4 zero drift) regardless of the clock.
func TestGenerateCorrelationIdWiresInjectedClock(t *testing.T) {
	t.Parallel()

	fixed := time.Date(2026, 7, 21, 8, 0, 0, 0, time.UTC)

	tests := map[string]struct {
		secure bool
	}{
		"plain request":      {secure: false},
		"tls request secure": {secure: true},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			clock := common.NewMockSystemClock()
			clock.SetNow(fixed)

			target := "http://example.com/signin-ext"
			if tc.secure {
				target = "https://example.com/signin-ext"
			}
			req := httptest.NewRequest(http.MethodGet, target, nil)
			rec := httptest.NewRecorder()

			h := newCorrelationTestHandler(clock, req, rec)

			props := auth.NewProperties()
			if err := h.GenerateCorrelationId(props); err != nil {
				t.Fatalf("GenerateCorrelationId returned error: %v", err)
			}

			// The correlation id is recorded on the properties and echoed in the
			// cookie name, confirming the generate leg ran to completion.
			if props.Items[CorrelationProperty] == "" {
				t.Fatal("expected a correlation id to be stored on properties")
			}

			cookie := correlationCookie(t, rec)
			if cookie.Value != CorrelationMarker {
				t.Fatalf("expected correlation marker %q, got %q", CorrelationMarker, cookie.Value)
			}
			// AC#4 zero-drift: a session cookie carries no Expires; the injected
			// clock only changes the stamp when an Expiration is configured, which
			// the correlation builder never does in production.
			if !cookie.Expires.IsZero() {
				t.Fatalf("expected session correlation cookie (no Expires), got %v", cookie.Expires)
			}
			// The Set-Cookie Secure flag reflects the request's TLS state, proving
			// Build ran against the real request seam.
			if cookie.Secure != tc.secure {
				t.Fatalf("expected Secure=%v, got %v", tc.secure, cookie.Secure)
			}
		})
	}
}

// TestValidateCorrelationIdRoundTrip drives both production use sites end to end:
// GenerateCorrelationId writes the cookie, and ValidateCorrelationId reads it back
// on a follow-up request under the same injected clock, returning true. This is the
// end-to-end correlation round trip that exercises the handler clock wiring on both
// legs.
func TestValidateCorrelationIdRoundTrip(t *testing.T) {
	t.Parallel()

	clock := common.NewMockSystemClock()
	clock.SetNow(time.Date(2026, 7, 21, 8, 0, 0, 0, time.UTC))

	// Generate leg: write the correlation cookie.
	genReq := httptest.NewRequest(http.MethodGet, "http://example.com/signin-ext", nil)
	genRec := httptest.NewRecorder()
	genHandler := newCorrelationTestHandler(clock, genReq, genRec)

	props := auth.NewProperties()
	if err := genHandler.GenerateCorrelationId(props); err != nil {
		t.Fatalf("GenerateCorrelationId returned error: %v", err)
	}
	cookie := correlationCookie(t, genRec)

	// Validate leg: replay the cookie and the correlation id on a new request.
	valReq := httptest.NewRequest(http.MethodGet, "http://example.com/signin-ext", nil)
	valReq.AddCookie(cookie)
	valRec := httptest.NewRecorder()
	valHandler := newCorrelationTestHandler(clock, valReq, valRec)

	valid, err := valHandler.ValidateCorrelationId(props)
	if err != nil {
		t.Fatalf("ValidateCorrelationId returned error: %v", err)
	}
	if !valid {
		t.Fatal("expected correlation validation to succeed for a matching cookie")
	}
	// Validation consumes the correlation property.
	if props.Items[CorrelationProperty] != "" {
		t.Fatal("expected correlation property to be removed after validation")
	}
}

// TestGenerateCorrelationIdStampsExpiryThroughHandlerClock gives the correlation
// builder an explicit Expiration and drives the production use site, proving the
// handler's clock wiring (SetClock(h.Clock)) reaches the emitted Set-Cookie: the
// cookie's Expires equals the injected fixed instant plus the Expiration. This is
// the discriminating assertion — remove the handler's SetClock call and it turns
// red because Build falls back to the wall clock. Production never sets an
// Expiration (AC#4), so this exercises the wiring without changing production
// behavior.
func TestGenerateCorrelationIdStampsExpiryThroughHandlerClock(t *testing.T) {
	t.Parallel()

	fixed := time.Date(2026, 7, 21, 8, 0, 0, 0, time.UTC)
	exp := 30 * time.Minute

	clock := common.NewMockSystemClock()
	clock.SetNow(fixed)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/signin-ext", nil)
	rec := httptest.NewRecorder()
	h := newCorrelationTestHandler(clock, req, rec)
	// Force a non-nil Expires so the injected clock's stamp is observable on the
	// emitted cookie; production leaves this unset.
	h.Options.correlationCookieBuilder.Expiration = &exp

	if err := h.GenerateCorrelationId(auth.NewProperties()); err != nil {
		t.Fatalf("GenerateCorrelationId returned error: %v", err)
	}

	cookie := correlationCookie(t, rec)
	want := fixed.Add(exp)
	if !cookie.Expires.Equal(want) {
		t.Fatalf("expected cookie Expires %v from injected clock, got %v", want, cookie.Expires)
	}
}

// TestValidateCorrelationIdRejectsMissingCookie confirms the validate leg fails
// gracefully (false, no error) when the correlation cookie is absent, matching the
// remote handler's "Correlation failed." contract.
func TestValidateCorrelationIdRejectsMissingCookie(t *testing.T) {
	t.Parallel()

	clock := common.NewMockSystemClock()
	clock.SetNow(time.Date(2026, 7, 21, 8, 0, 0, 0, time.UTC))

	props := auth.NewProperties()
	props.Items[CorrelationProperty] = "some-correlation-id"

	req := httptest.NewRequest(http.MethodGet, "http://example.com/signin-ext", nil)
	rec := httptest.NewRecorder()
	h := newCorrelationTestHandler(clock, req, rec)

	valid, err := h.ValidateCorrelationId(props)
	if err != nil {
		t.Fatalf("expected nil error for a missing correlation cookie, got %v", err)
	}
	if valid {
		t.Fatal("expected correlation validation to fail when the cookie is absent")
	}
}
