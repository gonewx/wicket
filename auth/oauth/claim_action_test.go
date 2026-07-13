// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package oauth_test

import (
	"testing"

	"github.com/gonewx/wicket/auth/oauth"
	"github.com/gonewx/wicket/claims"
)

func TestDeleteClaimActionRemovesMatchingClaims(t *testing.T) {
	t.Parallel()

	identity := claims.NewClaimsIdentity()
	identity.AddClaim(claims.NewClaim(claims.WithClaimType("role"), claims.WithClaimValue("admin")))
	identity.AddClaim(claims.NewClaim(claims.WithClaimType("role"), claims.WithClaimValue("user")))
	identity.AddClaim(claims.NewClaim(claims.WithClaimType("sub"), claims.WithClaimValue("user-1")))

	action := oauth.NewDeleteClaimAction("role")
	action.Run("", identity, "")

	remaining := identity.Claims()
	if len(remaining) != 1 {
		t.Fatalf("expected 1 claim after delete, got %d", len(remaining))
	}
	if remaining[0].Type != "sub" {
		t.Fatalf("expected remaining claim type %q, got %q", "sub", remaining[0].Type)
	}
}

func TestDeleteClaimActionTyp(t *testing.T) {
	t.Parallel()

	action := oauth.NewDeleteClaimAction("email")
	if action.Typ() != "email" {
		t.Fatalf("expected type %q, got %q", "email", action.Typ())
	}
}

func TestDeleteClaimActionNoMatchIsNoOp(t *testing.T) {
	t.Parallel()

	identity := claims.NewClaimsIdentity()
	identity.AddClaim(claims.NewClaim(claims.WithClaimType("sub"), claims.WithClaimValue("user-1")))

	action := oauth.NewDeleteClaimAction("nonexistent")
	action.Run("", identity, "")

	if len(identity.Claims()) != 1 {
		t.Fatal("expected no claims removed")
	}
}

func TestJsonKeyClaimActionAddsClaimFromJson(t *testing.T) {
	t.Parallel()

	identity := claims.NewClaimsIdentity()
	action := oauth.NewJsonKeyClaimAction("email", "email")

	userData := `{"email": "test@example.com", "name": "Test User"}`
	action.Run(userData, identity, "issuer-1")

	found := identity.FindAll("email")
	if len(found) != 1 {
		t.Fatalf("expected 1 email claim, got %d", len(found))
	}
	if found[0].Value != "test@example.com" {
		t.Fatalf("expected value %q, got %v", "test@example.com", found[0].Value)
	}
	if found[0].Issuer != "issuer-1" {
		t.Fatalf("expected issuer %q, got %q", "issuer-1", found[0].Issuer)
	}
}

func TestJsonKeyClaimActionHandlesArray(t *testing.T) {
	t.Parallel()

	identity := claims.NewClaimsIdentity()
	action := oauth.NewJsonKeyClaimAction("role", "roles")

	userData := `{"roles": ["admin", "editor"]}`
	action.Run(userData, identity, "issuer")

	found := identity.FindAll("role")
	if len(found) != 2 {
		t.Fatalf("expected 2 role claims, got %d", len(found))
	}
}

func TestJsonKeyClaimActionMissingKeyIsNoOp(t *testing.T) {
	t.Parallel()

	identity := claims.NewClaimsIdentity()
	action := oauth.NewJsonKeyClaimAction("email", "email")

	action.Run(`{"name": "Test"}`, identity, "issuer")

	if len(identity.Claims()) != 0 {
		t.Fatal("expected no claims added for missing key")
	}
}

func TestJsonKeyClaimActionTyp(t *testing.T) {
	t.Parallel()

	action := oauth.NewJsonKeyClaimAction("sub", "sub")
	if action.Typ() != "sub" {
		t.Fatalf("expected type %q, got %q", "sub", action.Typ())
	}
}

func TestJsonSubKeyClaimActionAddsNestedClaim(t *testing.T) {
	t.Parallel()

	identity := claims.NewClaimsIdentity()
	action := oauth.NewJsonSubKeyClaimAction("city", "address", "city")

	userData := `{"address": {"city": "Tokyo", "country": "JP"}}`
	action.Run(userData, identity, "issuer")

	found := identity.FindAll("city")
	if len(found) != 1 {
		t.Fatalf("expected 1 city claim, got %d", len(found))
	}
	if found[0].Value != "Tokyo" {
		t.Fatalf("expected value %q, got %v", "Tokyo", found[0].Value)
	}
}

func TestJsonSubKeyClaimActionMissingSubKeyIsNoOp(t *testing.T) {
	t.Parallel()

	identity := claims.NewClaimsIdentity()
	action := oauth.NewJsonSubKeyClaimAction("zip", "address", "zip")

	userData := `{"address": {"city": "Tokyo"}}`
	action.Run(userData, identity, "issuer")

	if len(identity.Claims()) != 0 {
		t.Fatal("expected no claims for missing subkey")
	}
}

func TestJsonSubKeyClaimActionMissingTopKeyIsNoOp(t *testing.T) {
	t.Parallel()

	identity := claims.NewClaimsIdentity()
	action := oauth.NewJsonSubKeyClaimAction("city", "location", "city")

	userData := `{"address": {"city": "Tokyo"}}`
	action.Run(userData, identity, "issuer")

	if len(identity.Claims()) != 0 {
		t.Fatal("expected no claims for missing top-level key")
	}
}

func TestJsonSubKeyClaimActionHandlesArray(t *testing.T) {
	t.Parallel()

	identity := claims.NewClaimsIdentity()
	action := oauth.NewJsonSubKeyClaimAction("tag", "meta", "tags")

	userData := `{"meta": {"tags": ["a", "b"]}}`
	action.Run(userData, identity, "issuer")

	found := identity.FindAll("tag")
	if len(found) != 2 {
		t.Fatalf("expected 2 tag claims, got %d", len(found))
	}
}
