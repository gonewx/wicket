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

func TestSettlePromptValuesAdvertisement(t *testing.T) {
	t.Parallel()
	key := wicket.DiscoveryPromptValuesSupported
	authorize := map[string]any{wicket.DiscoveryAuthorizationEndpoint: "https://as.example/connect/authorize"}
	withAuthorize := func(extra map[string]any) map[string]any {
		document := map[string]any{}
		for k, v := range authorize {
			document[k] = v
		}
		for k, v := range extra {
			document[k] = v
		}
		return document
	}
	all := []string{"none", "login", "consent", "select_account", "create"}
	cases := map[string]struct {
		document map[string]any
		served   bool
		want     any
		warns    bool
	}{
		"not served":                     {document: withAuthorize(nil)},
		"served":                         {document: withAuthorize(nil), served: true, want: all},
		"served without authorization":   {document: map[string]any{}, served: true},
		"custom entry while not served":  {document: withAuthorize(map[string]any{key: []string{"create"}}), warns: true},
		"custom entry while served":      {document: withAuthorize(map[string]any{key: []string{"none"}}), served: true, want: all, warns: true},
		"custom entry without authorize": {document: map[string]any{key: []string{"create"}}, served: true, warns: true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var logs bytes.Buffer
			settlePromptValuesAdvertisement(tc.document, tc.served, slog.New(slog.NewTextHandler(&logs, nil)))
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

func TestSettlePromptValuesAdvertisementDoesNotAliasTheSupportedModes(t *testing.T) {
	t.Parallel()
	document := map[string]any{wicket.DiscoveryAuthorizationEndpoint: "https://as.example/connect/authorize"}
	settlePromptValuesAdvertisement(document, true, nil)
	document[wicket.DiscoveryPromptValuesSupported].([]string)[0] = "changed"
	if wicket.SupportedPromptModes[0] != wicket.PromptModesNone {
		t.Fatalf("supported prompt modes changed: %v", wicket.SupportedPromptModes)
	}
}

func TestServeAccountCreation(t *testing.T) {
	t.Parallel()
	handler := &DiscoveryHandler{}
	handler.ServeAccountCreation()
	if !handler.servesAccountCreation {
		t.Fatal("account creation not recorded")
	}
}
