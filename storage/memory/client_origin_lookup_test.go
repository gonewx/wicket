// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package memory

import (
	"context"
	"sort"
	"testing"

	"github.com/gonewx/wicket/storage/models"
)

func TestMemoryClientStoreFindClientsByAllowedOrigin(t *testing.T) {
	t.Parallel()

	store, err := NewMemoryClientStore([]*models.Client{
		{ClientId: "a", Enabled: true, AllowedCorsOrigins: []string{"https://a.example", "https://shared.example"}},
		{ClientId: "b", Enabled: false, AllowedCorsOrigins: []string{"https://shared.example"}},
		{ClientId: "c", Enabled: true},
	})
	if err != nil {
		t.Fatalf("construct store: %v", err)
	}

	tests := map[string]struct {
		origin string
		want   []string
	}{
		"single match":                  {origin: "https://a.example", want: []string{"a"}},
		"disabled clients are returned": {origin: "https://shared.example", want: []string{"a", "b"}},
		"miss returns empty":            {origin: "https://none.example", want: []string{}},
		"match is exact not prefix":     {origin: "https://a.example/", want: []string{}},
		"match is case sensitive":       {origin: "https://A.example", want: []string{}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			clients, err := store.FindClientsByAllowedOrigin(context.Background(), tc.origin)
			if err != nil {
				t.Fatalf("FindClientsByAllowedOrigin: %v", err)
			}
			if clients == nil {
				t.Fatal("miss must return an empty slice, not nil")
			}
			got := make([]string, 0, len(clients))
			for _, client := range clients {
				got = append(got, client.ClientId)
			}
			sort.Strings(got)
			if len(got) != len(tc.want) {
				t.Fatalf("clients = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("clients = %v, want %v", got, tc.want)
				}
			}
		})
	}
}
