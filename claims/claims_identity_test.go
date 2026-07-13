// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package claims

import (
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
