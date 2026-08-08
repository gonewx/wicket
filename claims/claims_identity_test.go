// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package claims

import (
	"encoding/json"
	"testing"
)

func TestCloneDeepCopiesClaims(t *testing.T) {
	t.Parallel()

	identity := NewClaimsIdentity(
		WithAuthenticationType("bearer"),
	)
	identity.NameClaimType = "name"
	identity.RoleClaimType = "role"
	identity.AddClaim(NewClaim(
		WithClaimType("sub"),
		WithClaimValue("user-1"),
		WithClaimIssuer("issuer-a"),
	))

	cloned := identity.Clone()

	if cloned == identity {
		t.Fatal("expected different pointer")
	}
	if cloned.AuthenticationType() != "bearer" {
		t.Fatalf("expected auth type %q, got %q", "bearer", cloned.AuthenticationType())
	}
	if cloned.NameClaimType != "name" {
		t.Fatalf("expected NameClaimType %q, got %q", "name", cloned.NameClaimType)
	}
	if cloned.RoleClaimType != "role" {
		t.Fatalf("expected RoleClaimType %q, got %q", "role", cloned.RoleClaimType)
	}
	if len(cloned.Claims()) != 1 {
		t.Fatalf("expected 1 claim, got %d", len(cloned.Claims()))
	}

	origClaim := identity.Claims()[0]
	clonedClaim := cloned.Claims()[0]
	if origClaim == clonedClaim {
		t.Fatal("expected cloned claim to be a different pointer")
	}
	if clonedClaim.Type != "sub" || clonedClaim.Value != "user-1" {
		t.Fatal("expected claim values preserved in clone")
	}
}

func TestCloneNilReturnsNil(t *testing.T) {
	t.Parallel()

	var identity *ClaimsIdentity
	cloned := identity.Clone()
	if cloned != nil {
		t.Fatal("expected nil from Clone on nil receiver")
	}
}

func TestCloneMutationIsolation(t *testing.T) {
	t.Parallel()

	identity := NewClaimsIdentity(WithAuthenticationType("cookie"))
	identity.AddClaim(NewClaim(
		WithClaimType("sub"),
		WithClaimValue("user-1"),
	))

	cloned := identity.Clone()
	cloned.AddClaim(NewClaim(
		WithClaimType("email"),
		WithClaimValue("test@example.com"),
	))

	if len(identity.Claims()) != 1 {
		t.Fatalf("expected original to still have 1 claim, got %d", len(identity.Claims()))
	}
	if len(cloned.Claims()) != 2 {
		t.Fatalf("expected clone to have 2 claims, got %d", len(cloned.Claims()))
	}
}

func TestTryRemoveClaimSuccess(t *testing.T) {
	t.Parallel()

	identity := NewClaimsIdentity()
	claim := NewClaim(WithClaimType("role"), WithClaimValue("admin"))
	identity.AddClaim(claim)

	removed := identity.TryRemoveClaim(claim)
	if !removed {
		t.Fatal("expected TryRemoveClaim to return true")
	}
	if len(identity.Claims()) != 0 {
		t.Fatalf("expected 0 claims after removal, got %d", len(identity.Claims()))
	}
}

func TestTryRemoveClaimNotFound(t *testing.T) {
	t.Parallel()

	identity := NewClaimsIdentity()
	identity.AddClaim(NewClaim(WithClaimType("sub"), WithClaimValue("user-1")))

	other := NewClaim(WithClaimType("sub"), WithClaimValue("user-1"))

	removed := identity.TryRemoveClaim(other)
	if removed {
		t.Fatal("expected TryRemoveClaim to return false for different pointer")
	}
	if len(identity.Claims()) != 1 {
		t.Fatal("expected claim count unchanged")
	}
}

func TestTryRemoveClaimNilReceiver(t *testing.T) {
	t.Parallel()

	var identity *ClaimsIdentity
	claim := NewClaim(WithClaimType("sub"), WithClaimValue("x"))
	if identity.TryRemoveClaim(claim) {
		t.Fatal("expected false on nil receiver")
	}
}

func TestTryRemoveClaimNilClaim(t *testing.T) {
	t.Parallel()

	identity := NewClaimsIdentity()
	if identity.TryRemoveClaim(nil) {
		t.Fatal("expected false for nil claim")
	}
}

func TestTryRemoveClaimMiddleElement(t *testing.T) {
	t.Parallel()

	identity := NewClaimsIdentity()
	c1 := NewClaim(WithClaimType("a"), WithClaimValue("1"))
	c2 := NewClaim(WithClaimType("b"), WithClaimValue("2"))
	c3 := NewClaim(WithClaimType("c"), WithClaimValue("3"))
	identity.AddClaim(c1)
	identity.AddClaim(c2)
	identity.AddClaim(c3)

	identity.TryRemoveClaim(c2)

	remaining := identity.Claims()
	if len(remaining) != 2 {
		t.Fatalf("expected 2 claims, got %d", len(remaining))
	}
	if remaining[0] != c1 || remaining[1] != c3 {
		t.Fatal("expected c1 and c3 to remain in order")
	}
}

func TestClaimsIdentityJSONRoundTrip(t *testing.T) {
	t.Parallel()

	identity := NewClaimsIdentity(
		WithAuthenticationType("wicket"),
	)
	identity.NameClaimType = "name"
	identity.RoleClaimType = "role"
	identity.AddClaim(NewClaim(
		WithClaimType("sub"),
		WithClaimValue("1"),
	))
	identity.AddClaim(NewClaim(
		WithClaimType("name"),
		WithClaimValue("alice"),
		WithClaimIssuer("issuer-a"),
		WithClaimOriginalIssuer("issuer-a"),
		WithClaimValueType("string"),
	))

	data, err := json.Marshal(identity)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded ClaimsIdentity
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.AuthenticationType() != "wicket" {
		t.Errorf("AuthenticationType() = %q, want %q", decoded.AuthenticationType(), "wicket")
	}
	if decoded.NameClaimType != "name" {
		t.Errorf("NameClaimType = %q, want %q", decoded.NameClaimType, "name")
	}
	if decoded.RoleClaimType != "role" {
		t.Errorf("RoleClaimType = %q, want %q", decoded.RoleClaimType, "role")
	}
	if len(decoded.Claims()) != 2 {
		t.Fatalf("Claims() = %d, want 2", len(decoded.Claims()))
	}
	sub := decoded.FindFirst("sub")
	if sub == nil || sub.Value != "1" {
		t.Errorf("sub claim lost in round trip: %+v", sub)
	}
	name := decoded.FindFirst("name")
	if name == nil || name.Value != "alice" || name.Issuer != "issuer-a" || name.OriginalIssuer != "issuer-a" || name.ValueType != "string" {
		t.Errorf("name claim fields lost in round trip: %+v", name)
	}
}

func TestClaimsIdentityJSONRoundTripThroughPrincipal(t *testing.T) {
	t.Parallel()

	principal := NewClaimsPrincipal(
		WithClaimsPrincipalIdentity(NewClaimsIdentity(
			WithAuthenticationType("wicket"),
			WithClaims([]*Claim{
				NewClaim(WithClaimType("sub"), WithClaimValue("1")),
				NewClaim(WithClaimType("name"), WithClaimValue("alice")),
			}),
		)),
	)

	data, err := json.Marshal(principal)
	if err != nil {
		t.Fatalf("marshal principal: %v", err)
	}

	var decoded ClaimsPrincipal
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal principal: %v", err)
	}
	if len(decoded.Identities) != 1 {
		t.Fatalf("Identities = %d, want 1", len(decoded.Identities))
	}
	identity := decoded.Identities[0]
	if identity.AuthenticationType() != "wicket" {
		t.Errorf("AuthenticationType() = %q, want %q", identity.AuthenticationType(), "wicket")
	}
	if got := len(identity.Claims()); got != 2 {
		t.Fatalf("Claims() = %d, want 2", got)
	}
	if sub := identity.FindFirst("sub"); sub == nil || sub.Value != "1" {
		t.Errorf("sub claim lost in round trip: %+v", sub)
	}
}

func TestClaimsIdentityJSONRoundTripEmptyFields(t *testing.T) {
	t.Parallel()

	data, err := json.Marshal(NewClaimsIdentity())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded ClaimsIdentity
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.AuthenticationType() != "" || decoded.NameClaimType != "" || decoded.RoleClaimType != "" {
		t.Errorf("zero identity did not round trip: %+v", decoded)
	}
	if len(decoded.Claims()) != 0 {
		t.Errorf("zero identity claims = %d, want 0", len(decoded.Claims()))
	}
}
