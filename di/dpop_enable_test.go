// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package di

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket/clientassertion"
	"github.com/gonewx/wicket/clientcert"
	"github.com/gonewx/wicket/dpop"
	"github.com/gonewx/wicket/handlers"
	"github.com/gonewx/wicket/replay"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/storage"
	storage_models "github.com/gonewx/wicket/storage/models"
)

func dpopRequiringClient(id string) *storage_models.Client {
	client := storage_models.NewClient()
	client.ClientId = id
	client.RequireDPoP = true
	return client
}

func TestDPoPNotEnabledLeavesTheAssemblyAsItWas(t *testing.T) {
	root, cfg := newAssertionRoot(t)
	var seamReads atomic.Int64
	cfg.SetReplayRegistryProvider(func() replay.Registry {
		seamReads.Add(1)
		return replay.NewMemoryRegistry()
	})
	cfg.SetClients([]*storage_models.Client{dpopRequiringClient("dpop-client")})
	cfg.Freeze()

	if cfg.DPoPEnabled() {
		t.Fatal("DPoP reported enabled")
	}
	if got := cfg.DPoPOptions(); !reflect.DeepEqual(got, dpop.Options{}) {
		t.Fatalf("options of a feature that is not enabled: %+v", got)
	}
	handler := godi.GetRequired[*handlers.TokenHandler](root)
	if held := reflect.ValueOf(handler).Elem().FieldByName("dpop"); !held.IsNil() {
		t.Fatal("token handler holds DPoP although it is not enabled")
	}
	if confirmation := accessTokenConfirmationFromProvider(root); confirmation != nil {
		t.Fatalf("access token confirmation %T without a binding feature", confirmation)
	}
	_ = godi.GetRequired[*handlers.DiscoveryHandler](root)

	// A client requiring DPoP does not load while DPoP is not enabled.
	client, err := godi.GetRequired[storage.ClientStore](root).FindClientById(context.Background(), "dpop-client")
	if err == nil || client != nil {
		t.Fatalf("client loaded although DPoP is not enabled: %+v, %v", client, err)
	}
	if !errors.Is(err, storage.ErrInvalidClientConfiguration) {
		t.Fatalf("client store error %v, want ErrInvalidClientConfiguration", err)
	}

	if got := seamReads.Load(); got != 0 {
		t.Fatalf("replay registry seam read %d times without the feature", got)
	}
}

func TestDPoPEnabledAfterTheRootIsBuilt(t *testing.T) {
	root, cfg := newAssertionRoot(t)
	var seamReads atomic.Int64
	cfg.SetReplayRegistryProvider(func() replay.Registry {
		seamReads.Add(1)
		return replay.NewMemoryRegistry()
	})
	cfg.SetClients([]*storage_models.Client{dpopRequiringClient("dpop-client")})
	cfg.EnableDPoP(dpop.Options{SigningAlgorithms: []string{"ES256"}})
	cfg.Freeze()

	if !cfg.DPoPEnabled() || cfg.PrivateKeyJwtEnabled() {
		t.Fatalf("dpop=%v private_key_jwt=%v", cfg.DPoPEnabled(), cfg.PrivateKeyJwtEnabled())
	}
	options := cfg.DPoPOptions()
	if !slices.Equal(options.SigningAlgorithms, []string{"ES256"}) || options.ProofLifetime != time.Minute || options.ClockSkew != time.Minute {
		t.Fatalf("options %+v", options)
	}
	handler := godi.GetRequired[*handlers.TokenHandler](root)
	if held := reflect.ValueOf(handler).Elem().FieldByName("dpop"); held.IsNil() {
		t.Fatal("token handler holds no DPoP although it is enabled")
	}
	confirmation := accessTokenConfirmationFromProvider(root)
	if _, ok := confirmation.(dpop.AccessTokenBinder); !ok {
		t.Fatalf("access token confirmation %T, want the DPoP binder", confirmation)
	}
	client, err := godi.GetRequired[storage.ClientStore](root).FindClientById(context.Background(), "dpop-client")
	if err != nil || client == nil || !client.RequireDPoP {
		t.Fatalf("client %+v, %v", client, err)
	}
	// Building the handler resolves the lazy registry wrapper but not the
	// host's registry.
	if got := seamReads.Load(); got != 0 {
		t.Fatalf("replay registry seam read %d times before first use", got)
	}
}

func TestDPoPAndClientCertificateConfirmationsCombine(t *testing.T) {
	root, cfg := newAssertionRoot(t)
	cfg.SetReplayRegistry(replay.NewMemoryRegistry())
	cfg.EnableDPoP(dpop.Options{})
	cfg.EnableClientCertificateAuthentication(clientcert.Options{})
	cfg.Freeze()

	confirmation := accessTokenConfirmationFromProvider(root)
	if confirmation == nil {
		t.Fatal("no confirmation")
	}
	if _, ok := confirmation.(dpop.AccessTokenBinder); ok {
		t.Fatal("only the DPoP binder while both features are enabled")
	}
	// The certificate binder consults the client store; an unknown client
	// fails closed, which shows it takes part.
	request, _ := http.NewRequest(http.MethodPost, "https://as.example/connect/token", nil)
	if _, err := confirmation.Confirmation(dpop.WithProof(context.Background(), "tp"), request, "unknown"); err == nil {
		t.Fatal("the certificate binder did not take part")
	}
	var _ services.AccessTokenConfirmation = confirmation
}

func TestFreezeRequirementsOfDPoP(t *testing.T) {
	t.Run("registry neither injected nor fallback declared", func(t *testing.T) {
		cfg := NewServerConfig()
		cfg.AllowInMemoryFallback()
		cfg.EnableDPoP(dpop.Options{})
		text := panicText(t, cfg.Freeze)
		if !strings.Contains(text, "replay registry") || !strings.Contains(text, "dpop") {
			t.Fatalf("panic text %q", text)
		}
	})
	t.Run("registry injected", func(t *testing.T) {
		cfg := NewServerConfig()
		cfg.AllowInMemoryFallback()
		cfg.SetReplayRegistry(replay.NewMemoryRegistry())
		cfg.EnableDPoP(dpop.Options{})
		cfg.Freeze()
	})
	t.Run("invalid options", func(t *testing.T) {
		for name, options := range map[string]dpop.Options{
			"symmetric algorithm": {SigningAlgorithms: []string{"HS256"}},
			"none":                {SigningAlgorithms: []string{"none"}},
			"skew":                {ClockSkew: time.Hour},
			"lifetime":            {ProofLifetime: time.Hour},
			"negative":            {ProofLifetime: -time.Second},
		} {
			cfg := NewServerConfig()
			cfg.AllowInMemoryFallback()
			cfg.SetReplayRegistry(replay.NewMemoryRegistry())
			cfg.EnableDPoP(options)
			if text := panicText(t, cfg.Freeze); !strings.HasPrefix(text, "dpop options invalid: ") {
				t.Fatalf("%s: panic text %q", name, text)
			}
		}
	})
	t.Run("enabling after Freeze", func(t *testing.T) {
		cfg := NewServerConfig()
		cfg.AllowInMemoryFallback()
		cfg.Freeze()
		text := panicText(t, func() { cfg.EnableDPoP(dpop.Options{}) })
		if !strings.Contains(text, "EnableDPoP") || !strings.Contains(text, "after Freeze") {
			t.Fatalf("panic text %q", text)
		}
		if cfg.DPoPEnabled() {
			t.Fatal("feature enabled by a rejected call")
		}
	})
	t.Run("options are copies", func(t *testing.T) {
		cfg := NewServerConfig()
		algorithms := []string{"ES256"}
		cfg.EnableDPoP(dpop.Options{SigningAlgorithms: algorithms})
		algorithms[0] = "RS256"
		got := cfg.DPoPOptions()
		got.SigningAlgorithms[0] = "PS256"
		if !slices.Equal(cfg.DPoPOptions().SigningAlgorithms, []string{"ES256"}) {
			t.Fatalf("options shared: %v", cfg.DPoPOptions().SigningAlgorithms)
		}
		if !slices.Equal(dpop.DefaultOptions().SigningAlgorithms, clientassertion.SupportedSigningAlgorithms()) {
			t.Fatal("default algorithms changed")
		}
	})
}
