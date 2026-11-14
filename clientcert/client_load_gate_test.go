// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package clientcert

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"testing"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/clientassertion"
	"github.com/gonewx/wicket/storage"
	storage_models "github.com/gonewx/wicket/storage/models"
)

type erroringClients struct{ err error }

func (s erroringClients) FindClientById(context.Context, string) (*storage_models.Client, error) {
	return nil, s.err
}

func TestClientLoadErrorsAreClassified(t *testing.T) {
	t.Parallel()

	infrastructure := errors.New("connection refused")
	tests := map[string]struct {
		err         error
		unavailable bool
	}{
		"not found goes to the inner validator": {err: storage.ErrNotFound},
		"invalid configuration goes to the inner validator": {
			err: fmt.Errorf("%w: client %q", storage.ErrInvalidClientConfiguration, pkiClientId),
		},
		"infrastructure failure is unavailable": {err: infrastructure, unavailable: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			a := NewClientAuthenticator(f.inner, erroringClients{err: tc.err}, nil, Options{TrustedAuthorities: poolOf(f.root.cert)},
				func(string) bool { return true }, fixedClock{now: testNow}, nil)

			result := a.Validate(tlsRequest(url.Values{"client_id": {pkiClientId}}, f.leaf.cert, f.intermediate.cert))
			if tc.unavailable {
				if !errors.Is(result.Error, clientassertion.ErrAuthenticationUnavailable) || !errors.Is(result.Error, tc.err) {
					t.Fatalf("result error = %v, want unavailable wrapping %v", result.Error, tc.err)
				}
				if errors.Is(result.Error, wicket.TokenErrorsInvalidClient) {
					t.Fatalf("store failure reported as invalid_client: %v", result.Error)
				}
				if f.inner.calls.Load() != 0 {
					t.Fatalf("inner validator ran after a store failure")
				}
				return
			}
			if f.inner.calls.Load() != 1 {
				t.Fatalf("inner validator calls = %d, want 1", f.inner.calls.Load())
			}
			if errors.Is(result.Error, clientassertion.ErrAuthenticationUnavailable) {
				t.Fatalf("rejected client reported as unavailable: %v", result.Error)
			}
		})
	}
}
