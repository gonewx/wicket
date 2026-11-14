// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"net/url"
	"testing"

	"github.com/gonewx/wicket"
	config_options "github.com/gonewx/wicket/config/options"
)

func TestMtlsEndpointAliasesAreWellFormedUrls(t *testing.T) {
	cases := []struct {
		name       string
		domainName string
		wantHost   string
		wantPath   string
	}{
		{name: "path form", domainName: "", wantHost: "wicket.test", wantPath: "/connect/mtls/token"},
		{name: "sub-domain form", domainName: "mtls", wantHost: "mtls.wicket.test", wantPath: "/connect/token"},
		{name: "domain form", domainName: "mtls.example.test", wantHost: "mtls.example.test", wantPath: "/connect/token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			generator := &DiscoveryResponseGenerator{options: &config_options.WicketOptions{
				MutualTls: &config_options.MutualTlsOptions{Enabled: true, DomainName: tc.domainName},
			}}
			raw := generator.constructMtlsEndpoint("https://wicket.test", "https://wicket.test", wicket.ProtocolRoutePathsToken)
			parsed, err := url.Parse(raw)
			if err != nil {
				t.Fatalf("alias %q does not parse: %v", raw, err)
			}
			if parsed.Scheme != "https" || parsed.Host != tc.wantHost || parsed.Path != tc.wantPath {
				t.Fatalf("alias %q: got scheme %q host %q path %q, want https %q %q", raw, parsed.Scheme, parsed.Host, parsed.Path, tc.wantHost, tc.wantPath)
			}
		})
	}
}
