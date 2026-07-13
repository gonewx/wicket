// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package auth

import (
	"fmt"
	"testing"

	"github.com/gonewx/wicket/claims"
)

func TestNewResultIsEmpty(t *testing.T) {
	t.Parallel()

	r := NewResult()
	if r.Ticket != nil {
		t.Fatal("expected nil Ticket")
	}
	if r.Principal != nil {
		t.Fatal("expected nil Principal")
	}
	if r.Properties != nil {
		t.Fatal("expected nil Properties")
	}
	if r.Failure != nil {
		t.Fatal("expected nil Failure")
	}
	if r.None {
		t.Fatal("expected None false")
	}
}

func TestSuccessPopulatesFields(t *testing.T) {
	t.Parallel()

	principal := claims.NewClaimsPrincipal()
	props := NewProperties()
	ticket := NewTicket(principal, "test-scheme", props)

	r := Success(ticket)

	if r.Ticket != ticket {
		t.Fatal("expected ticket set")
	}
	if r.Principal != principal {
		t.Fatal("expected principal set from ticket")
	}
	if r.Properties != props {
		t.Fatal("expected properties set from ticket")
	}
	if r.Failure != nil {
		t.Fatal("expected nil Failure")
	}
}

func TestFailPopulatesFailure(t *testing.T) {
	t.Parallel()

	err := fmt.Errorf("auth failed")
	r := Fail(err)

	if r.Failure != err {
		t.Fatalf("expected Failure %v, got %v", err, r.Failure)
	}
	if r.Ticket != nil {
		t.Fatal("expected nil Ticket on failure")
	}
}

func TestResultSucceeded(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		result *Result
		want   bool
	}{
		"nil result": {
			result: nil,
			want:   false,
		},
		"empty result": {
			result: NewResult(),
			want:   false,
		},
		"failure result": {
			result: Fail(fmt.Errorf("err")),
			want:   false,
		},
		"success result": {
			result: Success(NewTicket(claims.NewClaimsPrincipal(), "s", nil)),
			want:   true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if tc.result.Succeeded() != tc.want {
				t.Fatalf("expected Succeeded()=%v, got %v", tc.want, tc.result.Succeeded())
			}
		})
	}
}

func TestNoResultSetsNone(t *testing.T) {
	t.Parallel()

	r := NoResult()
	if !r.None {
		t.Fatal("expected None true")
	}
}

// --- Ticket tests ---

func TestNewTicketDefaultProperties(t *testing.T) {
	t.Parallel()

	principal := claims.NewClaimsPrincipal()
	ticket := NewTicket(principal, "scheme", nil)

	if ticket.Properties == nil {
		t.Fatal("expected non-nil Properties when nil passed")
	}
	if ticket.Scheme != "scheme" {
		t.Fatalf("expected scheme %q, got %q", "scheme", ticket.Scheme)
	}
	if ticket.Principal != principal {
		t.Fatal("expected principal set")
	}
}

func TestNewTicketPreservesProperties(t *testing.T) {
	t.Parallel()

	props := NewProperties()
	props.Items["key"] = "value"
	principal := claims.NewClaimsPrincipal()

	ticket := NewTicket(principal, "s", props)

	if ticket.Properties != props {
		t.Fatal("expected the provided Properties to be preserved")
	}
	if ticket.Properties.Items["key"] != "value" {
		t.Fatal("expected Items preserved")
	}
}

func TestTicketCloneIsDeepCopy(t *testing.T) {
	t.Parallel()

	identity := claims.NewClaimsIdentity(claims.WithAuthenticationType("bearer"))
	identity.AddClaim(claims.NewClaim(
		claims.WithClaimType("sub"),
		claims.WithClaimValue("user-1"),
	))

	principal := claims.NewClaimsPrincipal()
	principal.Identities = append(principal.Identities, identity)

	props := NewProperties()
	props.Items["redirect"] = "/home"

	ticket := NewTicket(principal, "auth-scheme", props)
	clone := ticket.Clone()

	if clone == ticket {
		t.Fatal("expected different pointer")
	}
	if clone.Scheme != ticket.Scheme {
		t.Fatalf("expected scheme %q, got %q", ticket.Scheme, clone.Scheme)
	}

	clone.Properties.Items["redirect"] = "/changed"
	if ticket.Properties.Items["redirect"] != "/home" {
		t.Fatal("expected original Properties unchanged after clone mutation")
	}

	if len(clone.Principal.Identities) != 1 {
		t.Fatal("expected 1 identity in clone")
	}
	if clone.Principal.Identities[0] == identity {
		t.Fatal("expected cloned identity to be a different pointer")
	}
}
