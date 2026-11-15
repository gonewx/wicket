// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package wicket_test

import (
	"testing"

	"github.com/gonewx/wicket"
)

func TestAuthorizationServerMetadataPath(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		issuer  string
		want    string
		wantErr bool
	}{
		"no path":                {issuer: "https://as.example", want: "/.well-known/oauth-authorization-server"},
		"root path":              {issuer: "https://as.example/", want: "/.well-known/oauth-authorization-server"},
		"single segment":         {issuer: "https://as.example/tenant", want: "/.well-known/oauth-authorization-server/tenant"},
		"several segments":       {issuer: "https://as.example/tenant/one", want: "/.well-known/oauth-authorization-server/tenant/one"},
		"trailing slash":         {issuer: "https://as.example/tenant/one/", want: "/.well-known/oauth-authorization-server/tenant/one"},
		"several trailing slash": {issuer: "https://as.example/tenant/one///", want: "/.well-known/oauth-authorization-server/tenant/one"},
		"with port":              {issuer: "https://as.example:8443/tenant", want: "/.well-known/oauth-authorization-server/tenant"},
		"escaped character":      {issuer: "https://as.example/my%20tenant", want: "/.well-known/oauth-authorization-server/my%20tenant"},
		"unparsable":             {issuer: "https://as.example/%zz", wantErr: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := wicket.AuthorizationServerMetadataPath(tc.issuer)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("AuthorizationServerMetadataPath(%q) = %q, want an error", tc.issuer, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("AuthorizationServerMetadataPath(%q): %v", tc.issuer, err)
			}
			if got != tc.want {
				t.Fatalf("AuthorizationServerMetadataPath(%q) = %q, want %q", tc.issuer, got, tc.want)
			}
		})
	}
}
