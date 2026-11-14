// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package clientassertion

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/storage"
	storage_models "github.com/gonewx/wicket/storage/models"
)

type erroringClientStore struct{ err error }

func (s erroringClientStore) FindClientById(context.Context, string) (*storage_models.Client, error) {
	return nil, s.err
}

func TestClientAuthenticatorClassifiesClientLoadErrors(t *testing.T) {
	infrastructure := errors.New("connection refused")
	tests := map[string]struct {
		err         error
		unavailable bool
	}{
		"not found is invalid_client": {err: storage.ErrNotFound},
		"invalid configuration is invalid_client": {
			err: fmt.Errorf("%w: client %q", storage.ErrInvalidClientConfiguration, "assertion-client"),
		},
		"infrastructure failure is unavailable": {err: infrastructure, unavailable: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			s := newClientScene(t)
			authenticator := NewClientAuthenticator(s.inner, parserChain(), erroringClientStore{err: tc.err}, s.f.verifier, fixedIssuer(testAudience), s.f.logger)

			result := authenticator.Validate(formRequest(assertionValues(s.assertion(t, "assertion-client"))))
			if tc.unavailable {
				if result == nil || !errors.Is(result.Error, ErrAuthenticationUnavailable) || !errors.Is(result.Error, tc.err) {
					t.Fatalf("got %+v, want unavailable wrapping %v", result, tc.err)
				}
				if errors.Is(result.Error, wicket.TokenErrorsInvalidClient) || result.Client != nil {
					t.Fatalf("store failure reported as invalid_client: %+v", result)
				}
			} else {
				mustFailAsInvalidClient(t, result)
			}
			if s.inner.calls != 0 || s.f.registry.callCount() != 0 {
				t.Fatalf("inner calls %d, registry calls %d", s.inner.calls, s.f.registry.callCount())
			}
		})
	}
}
