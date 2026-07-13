// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package core_test

import (
	"testing"

	oauthcore "github.com/gonewx/wicket/auth/oauth/core"
)

func TestOptionsValidation(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		configure func(*oauthcore.Options)
		wantErr   string
	}{
		"rejects empty client id": {
			configure: func(o *oauthcore.Options) {
				o.SetClientSecret("secret")
				o.SetAuthorizationEndpoint("https://auth.example.com/authorize")
				o.SetTokenEndpoint("https://auth.example.com/token")
				o.SetCallbackPath("/oauth-callback")
			},
			wantErr: "clientId",
		},
		"rejects empty client secret": {
			configure: func(o *oauthcore.Options) {
				o.SetClientId("client-id")
				o.SetAuthorizationEndpoint("https://auth.example.com/authorize")
				o.SetTokenEndpoint("https://auth.example.com/token")
				o.SetCallbackPath("/oauth-callback")
			},
			wantErr: "clientSecret",
		},
		"rejects empty authorization endpoint": {
			configure: func(o *oauthcore.Options) {
				o.SetClientId("client-id")
				o.SetClientSecret("secret")
				o.SetTokenEndpoint("https://auth.example.com/token")
				o.SetCallbackPath("/oauth-callback")
			},
			wantErr: "authorizationEndpoint",
		},
		"rejects empty token endpoint": {
			configure: func(o *oauthcore.Options) {
				o.SetClientId("client-id")
				o.SetClientSecret("secret")
				o.SetAuthorizationEndpoint("https://auth.example.com/authorize")
				o.SetCallbackPath("/oauth-callback")
			},
			wantErr: "tokenEndpoint",
		},
		"rejects empty callback path": {
			configure: func(o *oauthcore.Options) {
				o.SetClientId("client-id")
				o.SetClientSecret("secret")
				o.SetAuthorizationEndpoint("https://auth.example.com/authorize")
				o.SetTokenEndpoint("https://auth.example.com/token")
			},
			wantErr: "CallbackPath",
		},
		"accepts valid options": {
			configure: func(o *oauthcore.Options) {
				o.SetClientId("client-id")
				o.SetClientSecret("secret")
				o.SetAuthorizationEndpoint("https://auth.example.com/authorize")
				o.SetTokenEndpoint("https://auth.example.com/token")
				o.SetCallbackPath("/oauth-callback")
			},
			wantErr: "",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			opts := oauthcore.NewOptions()
			tc.configure(opts)
			err := opts.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
			} else {
				if err == nil {
					t.Fatal("expected validation error, got nil")
				}
				if !contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected error containing %q, got %q", tc.wantErr, err.Error())
				}
			}
		})
	}
}

func TestRemoteOptionsValidation(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		scheme  string
		wantErr bool
	}{
		"rejects sign-in scheme same as handler scheme": {
			scheme:  "oauth-scheme",
			wantErr: true,
		},
		"accepts different sign-in scheme": {
			scheme:  "cookie-scheme",
			wantErr: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			opts := oauthcore.NewOptions()
			opts.SetClientId("id")
			opts.SetClientSecret("secret")
			opts.SetAuthorizationEndpoint("https://example.com/auth")
			opts.SetTokenEndpoint("https://example.com/token")
			opts.SetCallbackPath("/callback")
			opts.SetSignInScheme(tc.scheme)

			err := opts.ValidateByScheme("oauth-scheme")
			if tc.wantErr && err == nil {
				t.Fatal("expected validation error for same sign-in scheme")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestOptionsDefaultValues(t *testing.T) {
	t.Parallel()

	opts := oauthcore.NewOptions()
	if opts.BackchannelTimeout().Seconds() != 60 {
		t.Fatalf("expected default backchannel timeout 60s, got %v", opts.BackchannelTimeout())
	}
	if opts.ReturnUrlParameter() != "ReturnUrl" {
		t.Fatalf("expected default return url parameter 'ReturnUrl', got %q", opts.ReturnUrlParameter())
	}
	if opts.RemoteAuthenticationTimeout().Minutes() != 15 {
		t.Fatalf("expected default remote auth timeout 15min, got %v", opts.RemoteAuthenticationTimeout())
	}
	if opts.SaveTokens() {
		t.Fatal("expected SaveTokens default false")
	}
	if opts.UsePkce() {
		t.Fatal("expected UsePkce default false")
	}
}

func TestClaimActionsManagement(t *testing.T) {
	t.Parallel()

	opts := oauthcore.NewOptions()
	if len(opts.ClaimActions()) != 0 {
		t.Fatal("expected empty claim actions initially")
	}

	opts.AddScope("openid")
	opts.AddScope("profile")
	opts.AddScope("openid")

	if len(opts.Scope()) != 2 {
		t.Fatalf("expected 2 unique scopes, got %d", len(opts.Scope()))
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstr(s, substr))
}

func containsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
