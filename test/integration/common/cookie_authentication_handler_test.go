// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package common

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gonewx/wicket/auth"
	claimspkg "github.com/gonewx/wicket/claims"
)

// TestCookieAuthenticationHandlerPreservesClaimValueTypes verifies claim
// values keep their dynamic type across the SignIn/Authenticate cookie
// round-trip: JSON widens every number to float64, so integral values (such
// as an authentication-time epoch) must come back as int64 for typed
// consumers to read them.
func TestCookieAuthenticationHandlerPreservesClaimValueTypes(t *testing.T) {
	t.Parallel()

	scheme := &auth.Scheme{Name: "test-cookie"}

	identity := claimspkg.NewClaimsIdentity(claimspkg.WithAuthenticationType("local"))
	identity.AddClaim(&claimspkg.Claim{Type: "sub", Value: "alice"})
	identity.AddClaim(&claimspkg.Claim{Type: "auth_time", Value: int64(1_720_000_000)})
	identity.AddClaim(&claimspkg.Claim{Type: "ratio", Value: 1.5})
	principal := claimspkg.NewClaimsPrincipal()
	principal.Identities = append(principal.Identities, identity)

	signInRecorder := httptest.NewRecorder()
	signInHandler := newTestCookieAuthenticationHandler(nil)
	if err := signInHandler.Initialize(httptest.NewRequest(http.MethodGet, "/login", nil), signInRecorder, scheme); err != nil {
		t.Fatalf("initialize sign-in handler: %v", err)
	}
	if err := signInHandler.SignIn(principal, auth.NewProperties()); err != nil {
		t.Fatalf("sign in: %v", err)
	}
	cookies := signInRecorder.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("sign in wrote no cookie")
	}

	request := httptest.NewRequest(http.MethodGet, "/authorize", nil)
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	authenticateHandler := newTestCookieAuthenticationHandler(nil)
	if err := authenticateHandler.Initialize(request, httptest.NewRecorder(), scheme); err != nil {
		t.Fatalf("initialize authenticate handler: %v", err)
	}
	result, err := authenticateHandler.Authenticate()
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if result == nil || result.Principal == nil || len(result.Principal.Identities) != 1 {
		t.Fatalf("authenticate did not restore the principal: %+v", result)
	}

	restored := map[string]any{}
	for _, claim := range result.Principal.Identities[0].Claims() {
		restored[claim.Type] = claim.Value
	}
	if v, ok := restored["sub"].(string); !ok || v != "alice" {
		t.Fatalf("sub = %#v, want string \"alice\"", restored["sub"])
	}
	if v, ok := restored["auth_time"].(int64); !ok || v != 1_720_000_000 {
		t.Fatalf("auth_time = %#v, want int64 1720000000", restored["auth_time"])
	}
	if v, ok := restored["ratio"].(float64); !ok || v != 1.5 {
		t.Fatalf("ratio = %#v, want float64 1.5", restored["ratio"])
	}
}
