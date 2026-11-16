// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package di

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/clientassertion"
	"github.com/gonewx/wicket/clientcert"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/dpop"
	"github.com/gonewx/wicket/pushedauth"
	"github.com/gonewx/wicket/replay"
	storage_memory "github.com/gonewx/wicket/storage/memory"
	storage_models "github.com/gonewx/wicket/storage/models"
)

// highSecurityRoot returns a root whose configuration carries the seams of
// pushed authorization and the replay registry, nothing enabled.
func highSecurityRoot(t *testing.T) (*Root, *ServerConfig) {
	t.Helper()
	root, cfg := newAssertionRoot(t)
	cfg.SetPushedAuthorizationRequestStore(storage_memory.NewMemoryPushedAuthorizationRequestStore())
	cfg.SetPushedAuthorizationDataProtectionProvider(flippingProtector{})
	cfg.SetReplayRegistryProvider(func() replay.Registry { return replay.NewMemoryRegistry() })
	return root, cfg
}

// enableHighSecurityPrerequisites enables every feature the profile needs.
func enableHighSecurityPrerequisites(cfg *ServerConfig) {
	cfg.EnablePushedAuthorizationRequests(pushedauth.Options{})
	cfg.EnableDPoP(dpop.Options{})
	cfg.EnablePrivateKeyJwt(clientassertion.Options{})
}

func compliantProfileClient() *storage_models.Client {
	client := storage_models.NewClient()
	client.ClientId = "fapi"
	client.TokenEndpointAuthMethod = wicket.EndpointAuthenticationMethodsPrivateKeyJwt
	client.RequireDPoP = true
	client.AuthorizationCodeLifetime = 60
	client.RedirectUris = []string{"https://client.example/cb"}
	_ = client.SetAllowedGrantTypes(wicket.GrantTypesCode)
	return client
}

func TestHighSecurityProfileIsOffByDefault(t *testing.T) {
	root, cfg := highSecurityRoot(t)
	enableHighSecurityPrerequisites(cfg)
	cfg.Freeze()

	if cfg.HighSecurityProfileEnabled() {
		t.Fatal("profile reported enabled")
	}
	if cfg.AsymmetricRequestObjectsRequired() || cfg.ClientCredentialsAuthenticationRequired() || cfg.PushedAuthorizationRequestsOptions().RequireForAllClients {
		t.Fatal("a tightening is in effect without the profile")
	}
	if got := cfg.PrivateKeyJwtOptions().SigningAlgorithms; !slices.Equal(got, clientassertion.DefaultOptions().SigningAlgorithms) {
		t.Fatalf("private_key_jwt algorithms %v", got)
	}
	if got := cfg.DPoPOptions().SigningAlgorithms; !slices.Equal(got, dpop.DefaultOptions().SigningAlgorithms) {
		t.Fatalf("DPoP algorithms %v", got)
	}
	options := godi.GetRequired[*config_options.WicketOptions](root)
	if options.UseSeeOtherRedirects {
		t.Fatal("303 redirects turned on without the profile")
	}
	var nilConfig *ServerConfig
	if nilConfig.HighSecurityProfileEnabled() {
		t.Fatal("nil configuration reports the profile")
	}
}

func TestHighSecurityProfileEffectiveValues(t *testing.T) {
	orders := map[string]func(*ServerConfig){
		"profile first": func(cfg *ServerConfig) {
			cfg.EnableHighSecurityProfile()
			enableHighSecurityPrerequisites(cfg)
		},
		"profile last": func(cfg *ServerConfig) {
			enableHighSecurityPrerequisites(cfg)
			cfg.EnableHighSecurityProfile()
		},
	}
	for name, declare := range orders {
		t.Run(name, func(t *testing.T) {
			root, cfg := highSecurityRoot(t)
			// The host turned both protocol options off explicitly;
			// Freeze overrides that while the profile is enabled.
			declared := godi.GetRequired[*config_options.WicketOptions](root)
			declared.UseSeeOtherRedirects = false
			declared.EmitIssuerIdentificationResponseParameter = false
			declare(cfg)
			cfg.Freeze()

			if !cfg.AsymmetricRequestObjectsRequired() || !cfg.ClientCredentialsAuthenticationRequired() {
				t.Fatal("hardening options not in effect")
			}
			if !cfg.PushedAuthorizationRequestsOptions().RequireForAllClients {
				t.Fatal("pushed authorization not required")
			}
			if cfg.pushedAuthorizationOptions.RequireForAllClients {
				t.Fatal("the declared options were rewritten")
			}
			clients, _ := storage_memory.NewMemoryClientStore(nil)
			service, err := cfg.pushedAuthorizationService(clients, pushedTestClock{})
			if err != nil || !service.Required(nil) {
				t.Fatalf("service requires pushed authorization: %v", err)
			}
			if got := cfg.PrivateKeyJwtOptions().SigningAlgorithms; !slices.Equal(got, []string{"PS256", "ES256"}) {
				t.Fatalf("private_key_jwt algorithms %v", got)
			}
			if got := cfg.PrivateKeyJwtSigningAlgorithms(); !slices.Equal(got, []string{"PS256", "ES256"}) {
				t.Fatalf("validation algorithms %v", got)
			}
			if got := cfg.DPoPOptions().SigningAlgorithms; !slices.Equal(got, []string{"PS256", "ES256"}) {
				t.Fatalf("DPoP algorithms %v", got)
			}
			options := godi.GetRequired[*config_options.WicketOptions](root)
			if !options.UseSeeOtherRedirects || !options.EmitIssuerIdentificationResponseParameter {
				t.Fatalf("303=%v iss=%v", options.UseSeeOtherRedirects, options.EmitIssuerIdentificationResponseParameter)
			}
		})
	}
}

func TestHighSecurityProfileFreezeRequirements(t *testing.T) {
	cases := map[string]struct {
		declare func(*ServerConfig)
		want    []string
		absent  []string
	}{
		"nothing enabled": {
			declare: func(*ServerConfig) {},
			want:    []string{"pushed authorization requests are not enabled", "no sender constraint", "no asymmetric client authentication"},
		},
		"pushed authorization only": {
			declare: func(cfg *ServerConfig) { cfg.EnablePushedAuthorizationRequests(pushedauth.Options{}) },
			want:    []string{"no sender constraint", "no asymmetric client authentication"},
			absent:  []string{"pushed authorization requests are not enabled"},
		},
		"request_uri lifetime of 600 seconds": {
			declare: func(cfg *ServerConfig) {
				enableHighSecurityPrerequisites(cfg)
				cfg.EnablePushedAuthorizationRequests(pushedauth.Options{RequestUriLifetime: 600 * time.Second})
			},
			want: []string{"request_uri lifetime 10m0s is not below 10m0s"},
		},
		"private_key_jwt with RS256 only": {
			declare: func(cfg *ServerConfig) {
				enableHighSecurityPrerequisites(cfg)
				cfg.EnablePrivateKeyJwt(clientassertion.Options{SigningAlgorithms: []string{"RS256"}})
			},
			want: []string{"private_key_jwt accepts neither PS256 nor ES256"},
		},
		"DPoP with RS256 only": {
			declare: func(cfg *ServerConfig) {
				enableHighSecurityPrerequisites(cfg)
				cfg.EnableDPoP(dpop.Options{SigningAlgorithms: []string{"RS256"}})
			},
			want: []string{"DPoP accepts neither PS256 nor ES256"},
		},
		"static client with a shared secret": {
			declare: func(cfg *ServerConfig) {
				enableHighSecurityPrerequisites(cfg)
				shared := compliantProfileClient()
				shared.ClientId = "shared"
				shared.TokenEndpointAuthMethod = ""
				cfg.SetClients([]*storage_models.Client{compliantProfileClient(), shared})
			},
			want:   []string{`client "shared" conflicts with the profile: token endpoint authentication method`},
			absent: []string{`client "fapi"`},
		},
		"static client with RS256 assertions only": {
			declare: func(cfg *ServerConfig) {
				enableHighSecurityPrerequisites(cfg)
				rs256 := compliantProfileClient()
				rs256.ClientId = "rs256"
				rs256.TokenEndpointAuthSigningAlgorithms = []string{"RS256"}
				cfg.SetClients([]*storage_models.Client{compliantProfileClient(), rs256})
			},
			want:   []string{`client "rs256" conflicts with the profile: client lists a token endpoint authentication signing algorithm the server does not accept`},
			absent: []string{`client "fapi"`},
		},
		"static tls client listing ES256": {
			declare: func(cfg *ServerConfig) {
				enableHighSecurityPrerequisites(cfg)
				cfg.EnableClientCertificateAuthentication(clientcert.Options{})
				tls := compliantProfileClient()
				tls.ClientId = "tls"
				tls.TokenEndpointAuthMethod = wicket.EndpointAuthenticationMethodsTlsClientAuth
				tls.TokenEndpointAuthSigningAlgorithms = []string{"ES256"}
				cfg.SetClients([]*storage_models.Client{compliantProfileClient(), tls})
			},
			want:   []string{`client "tls" conflicts with the profile: `, "does not use private_key_jwt"},
			absent: []string{`client "fapi"`, "token endpoint authentication method"},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, cfg := highSecurityRoot(t)
			cfg.EnableHighSecurityProfile()
			tc.declare(cfg)
			text := panicText(t, cfg.Freeze)
			if !strings.HasPrefix(text, "high security profile cannot be served: ") {
				t.Fatalf("panic text %q", text)
			}
			for _, want := range tc.want {
				if !strings.Contains(text, want) {
					t.Fatalf("panic text %q lacks %q", text, want)
				}
			}
			for _, absent := range tc.absent {
				if strings.Contains(text, absent) {
					t.Fatalf("panic text %q holds %q", text, absent)
				}
			}
		})
	}
	t.Run("mutual TLS serves both prerequisites", func(t *testing.T) {
		_, cfg := highSecurityRoot(t)
		cfg.EnableHighSecurityProfile()
		cfg.EnablePushedAuthorizationRequests(pushedauth.Options{})
		cfg.EnableClientCertificateAuthentication(clientcert.Options{})
		cfg.Freeze()
	})
	t.Run("compliant static client", func(t *testing.T) {
		_, cfg := highSecurityRoot(t)
		cfg.EnableHighSecurityProfile()
		enableHighSecurityPrerequisites(cfg)
		es256 := compliantProfileClient()
		es256.ClientId = "es256"
		es256.TokenEndpointAuthSigningAlgorithms = []string{"ES256"}
		cfg.SetClients([]*storage_models.Client{compliantProfileClient(), es256})
		cfg.Freeze()
	})
	t.Run("RS256 static client without the profile", func(t *testing.T) {
		_, cfg := highSecurityRoot(t)
		enableHighSecurityPrerequisites(cfg)
		rs256 := compliantProfileClient()
		rs256.TokenEndpointAuthSigningAlgorithms = []string{"RS256"}
		cfg.SetClients([]*storage_models.Client{rs256})
		cfg.Freeze()
	})
	t.Run("enabling after Freeze", func(t *testing.T) {
		_, cfg := highSecurityRoot(t)
		cfg.Freeze()
		text := panicText(t, cfg.EnableHighSecurityProfile)
		if !strings.Contains(text, "EnableHighSecurityProfile") || !strings.Contains(text, "after Freeze") {
			t.Fatalf("panic text %q", text)
		}
	})
}
