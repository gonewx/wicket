// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"bytes"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/gonewx/wicket"
)

func TestSettleDPoPAdvertisement(t *testing.T) {
	t.Parallel()
	key := wicket.DiscoveryDPoPSigningAlgValuesSupported
	cases := map[string]struct {
		document   map[string]any
		served     bool
		algorithms []string
		want       any
		warns      bool
	}{
		"not served":                    {document: map[string]any{}, algorithms: []string{"ES256"}},
		"served":                        {document: map[string]any{}, served: true, algorithms: []string{"ES256", "PS256"}, want: []string{"ES256", "PS256"}},
		"served without algorithms":     {document: map[string]any{}, served: true},
		"custom entry while not served": {document: map[string]any{key: []string{"HS256"}}, warns: true},
		"custom entry while served":     {document: map[string]any{key: []string{"HS256"}}, served: true, algorithms: []string{"ES256"}, want: []string{"ES256"}, warns: true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var logs bytes.Buffer
			settleDPoPAdvertisement(tc.document, tc.served, tc.algorithms, slog.New(slog.NewTextHandler(&logs, nil)))
			got, present := tc.document[key]
			if tc.want == nil {
				if present {
					t.Fatalf("advertised %v", got)
				}
			} else if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("advertised %v, want %v", got, tc.want)
			}
			if warned := strings.Contains(logs.String(), key); warned != tc.warns {
				t.Fatalf("warned = %v, logs %q", warned, logs.String())
			}
		})
	}
}

func TestServeDPoPCopiesTheAlgorithms(t *testing.T) {
	t.Parallel()
	handler := &DiscoveryHandler{}
	algorithms := []string{"ES256"}
	handler.ServeDPoP(algorithms)
	algorithms[0] = "RS256"
	if !handler.servesDPoP || !reflect.DeepEqual(handler.dpopSigningAlgorithms, []string{"ES256"}) {
		t.Fatalf("served=%v algorithms=%v", handler.servesDPoP, handler.dpopSigningAlgorithms)
	}
}
