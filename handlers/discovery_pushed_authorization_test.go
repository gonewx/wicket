// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"testing"

	"github.com/gonewx/wicket"
	config_options "github.com/gonewx/wicket/config/options"
)

func TestSettlePushedAuthorizationAdvertisement(t *testing.T) {
	t.Parallel()

	const base = "https://op.example"
	routes := []string{"/" + wicket.ProtocolRoutePathsPushedAuthorization, "/" + wicket.ProtocolRoutePathsMtlsPushedAuthorization}
	tests := map[string]struct {
		declared   discoveryPushedAuthorization
		routes     []string
		domain     string
		aliases    bool
		wantURL    string
		wantFlag   any
		wantAlias  string
		hostValues bool
	}{
		"not served":            {routes: routes, aliases: true},
		"not served, host keys": {routes: routes, hostValues: true},
		"served, unrouted":      {declared: discoveryPushedAuthorization{served: true}, routes: nil},
		"served":                {declared: discoveryPushedAuthorization{served: true}, routes: routes, wantURL: base + "/connect/pushedauthorization", wantFlag: false},
		"served and required":   {declared: discoveryPushedAuthorization{served: true, required: true}, routes: routes, wantURL: base + "/connect/pushedauthorization", wantFlag: true},
		"path alias":            {declared: discoveryPushedAuthorization{served: true}, routes: routes, aliases: true, wantURL: base + "/connect/pushedauthorization", wantFlag: false, wantAlias: base + "/connect/mtls/pushedauthorization"},
		"domain alias":          {declared: discoveryPushedAuthorization{served: true}, routes: routes, aliases: true, domain: "mtls.op.example", wantURL: base + "/connect/pushedauthorization", wantFlag: false, wantAlias: "https://mtls.op.example/connect/pushedauthorization"},
		"sub-domain alias":      {declared: discoveryPushedAuthorization{served: true}, routes: routes, aliases: true, domain: "mtls", wantURL: base + "/connect/pushedauthorization", wantFlag: false, wantAlias: "https://mtls.op.example/connect/pushedauthorization"},
		"alias route missing":   {declared: discoveryPushedAuthorization{served: true}, routes: routes[:1], aliases: true, wantURL: base + "/connect/pushedauthorization", wantFlag: false},
		"no aliases entry":      {declared: discoveryPushedAuthorization{served: true}, routes: routes, wantURL: base + "/connect/pushedauthorization", wantFlag: false},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			options := config_options.NewWicketOptions()
			options.MutualTls.DomainName = tc.domain
			document := map[string]any{}
			if tc.aliases {
				document[wicket.DiscoveryMtlsEndpointAliases] = map[string]string{wicket.DiscoveryTokenEndpoint: base + "/connect/mtls/token"}
			}
			if tc.hostValues {
				document[wicket.DiscoveryPushedAuthorizationRequestEndpoint] = base + "/connect/pushedauthorization"
				document[wicket.DiscoveryRequirePushedAuthorizationRequests] = true
			}
			settlePushedAuthorizationAdvertisement(document, base+"/", options, discoveryAssembly{endpointPaths: tc.routes}, tc.declared)

			url, ok := document[wicket.DiscoveryPushedAuthorizationRequestEndpoint]
			if tc.wantURL == "" {
				if ok {
					t.Fatalf("endpoint advertised: %v", url)
				}
				if _, ok := document[wicket.DiscoveryRequirePushedAuthorizationRequests]; ok {
					t.Fatal("requirement advertised")
				}
			} else {
				if url != tc.wantURL {
					t.Fatalf("endpoint = %v, want %s", url, tc.wantURL)
				}
				if flag := document[wicket.DiscoveryRequirePushedAuthorizationRequests]; flag != tc.wantFlag {
					t.Fatalf("requirement = %v, want %v", flag, tc.wantFlag)
				}
			}
			aliases, _ := document[wicket.DiscoveryMtlsEndpointAliases].(map[string]string)
			alias, ok := aliases[wicket.DiscoveryPushedAuthorizationRequestEndpoint]
			if tc.wantAlias == "" {
				if ok {
					t.Fatalf("alias advertised: %s", alias)
				}
				return
			}
			if alias != tc.wantAlias {
				t.Fatalf("alias = %q, want %q", alias, tc.wantAlias)
			}
		})
	}
}
