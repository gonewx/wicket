// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package extensions

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/gonewx/wicket/storage"
	storage_models "github.com/gonewx/wicket/storage/models"
)

func TestIsClientRejected(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		err  error
		want bool
	}{
		"nil":                    {err: nil, want: false},
		"not found":              {err: storage.ErrNotFound, want: true},
		"wrapped not found":      {err: fmt.Errorf("load: %w", storage.ErrNotFound), want: true},
		"invalid configuration":  {err: storage.ErrInvalidClientConfiguration, want: true},
		"wrapped invalid":        {err: fmt.Errorf("%w: client %q", storage.ErrInvalidClientConfiguration, "c"), want: true},
		"infrastructure":         {err: errors.New("connection refused"), want: false},
		"other storage sentinel": {err: storage.ErrVersionConflict, want: false},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := IsClientRejected(tc.err); got != tc.want {
				t.Fatalf("IsClientRejected(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

type stubClientStore struct {
	client *storage_models.Client
	err    error
}

func (s stubClientStore) FindClientById(ctx context.Context, id string) (*storage_models.Client, error) {
	return s.client, s.err
}

func TestFindEnabledClientByIdKeepsErrorClasses(t *testing.T) {
	t.Parallel()

	infrastructure := errors.New("connection refused")
	invalid := fmt.Errorf("%w: client %q", storage.ErrInvalidClientConfiguration, "c")
	tests := map[string]struct {
		store    stubClientStore
		rejected bool
		wantErr  error
	}{
		"disabled":              {store: stubClientStore{client: &storage_models.Client{ClientId: "c"}}, rejected: true, wantErr: storage.ErrNotFound},
		"nil client":            {store: stubClientStore{}, rejected: true, wantErr: storage.ErrNotFound},
		"invalid configuration": {store: stubClientStore{err: invalid}, rejected: true, wantErr: storage.ErrInvalidClientConfiguration},
		"infrastructure":        {store: stubClientStore{err: infrastructure}, rejected: false, wantErr: infrastructure},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			client, err := FindEnabledClientById(context.Background(), tc.store, "c")
			if client != nil {
				t.Fatalf("client = %v, want nil", client)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if got := IsClientRejected(err); got != tc.rejected {
				t.Fatalf("IsClientRejected(%v) = %v, want %v", err, got, tc.rejected)
			}
		})
	}
}
