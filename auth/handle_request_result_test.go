// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package auth

import (
	"fmt"
	"testing"

	"github.com/gonewx/wicket/claims"
)

func TestHandleRequestResultFactories(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		factory func() *HandleRequestResult
		check   func(t *testing.T, r *HandleRequestResult)
	}{
		"NewHandleRequestResult is empty": {
			factory: NewHandleRequestResult,
			check: func(t *testing.T, r *HandleRequestResult) {
				if r.Handled || r.Skipped || r.None {
					t.Fatal("expected all flags false")
				}
			},
		},
		"Handle sets Handled": {
			factory: Handle,
			check: func(t *testing.T, r *HandleRequestResult) {
				if !r.Handled {
					t.Fatal("expected Handled true")
				}
				if r.Skipped {
					t.Fatal("expected Skipped false")
				}
			},
		},
		"SkipHandler sets Skipped": {
			factory: SkipHandler,
			check: func(t *testing.T, r *HandleRequestResult) {
				if !r.Skipped {
					t.Fatal("expected Skipped true")
				}
				if r.Handled {
					t.Fatal("expected Handled false")
				}
			},
		},
		"HandleRequestSkipResult sets Skipped": {
			factory: HandleRequestSkipResult,
			check: func(t *testing.T, r *HandleRequestResult) {
				if !r.Skipped {
					t.Fatal("expected Skipped true")
				}
			},
		},
		"HandleRequestNoResult sets None": {
			factory: HandleRequestNoResult,
			check: func(t *testing.T, r *HandleRequestResult) {
				if !r.None {
					t.Fatal("expected None true")
				}
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r := tc.factory()
			tc.check(t, r)
		})
	}
}

func TestHandleRequestSuccess(t *testing.T) {
	t.Parallel()

	principal := claims.NewClaimsPrincipal()
	props := NewProperties()
	ticket := NewTicket(principal, "s", props)

	r := HandleRequestSuccess(ticket)

	if r.Ticket != ticket {
		t.Fatal("expected ticket set")
	}
	if r.Properties != props {
		t.Fatal("expected properties from ticket")
	}
}

func TestHandleRequestFail(t *testing.T) {
	t.Parallel()

	err := fmt.Errorf("forbidden")
	props := NewProperties()

	r := HandleRequestFail(err, props)

	if r.Failure != err {
		t.Fatal("expected Failure set")
	}
	if r.Properties != props {
		t.Fatal("expected properties passed through")
	}
}
