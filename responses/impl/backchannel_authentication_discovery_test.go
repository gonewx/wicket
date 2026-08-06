// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"context"
	"log/slog"
	"testing"

	"github.com/gonewx/wicket"
	config_options "github.com/gonewx/wicket/config/options"
	core_models "github.com/gonewx/wicket/models"
	"github.com/gonewx/wicket/storage/memory"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/tokens"
	validators_impl "github.com/gonewx/wicket/validators/impl"
)

type cibaDiscoveryKeys struct{}

func (cibaDiscoveryKeys) GetSigningCredentials(ctx context.Context, allowed []string) (*tokens.SigningCredentials, error) {
	return nil, nil
}

func (cibaDiscoveryKeys) GetAllSigningCredentials(ctx context.Context) ([]*tokens.SigningCredentials, error) {
	return nil, nil
}

func (cibaDiscoveryKeys) GetValidationKeys(ctx context.Context) ([]*core_models.SecurityKeyInfo, error) {
	return nil, nil
}

func TestBackchannelAuthenticationDiscoveryMetadata(t *testing.T) {
	t.Parallel()

	identity := storage_models.NewIdentityResource()
	identity.Name = gois.StandardScopesOpenId
	resources, err := memory.NewMemoryResourcesStore([]*storage_models.IdentityResource{identity}, nil, nil)
	if err != nil {
		t.Fatalf("resource store: %v", err)
	}
	options := newDiscoveryTestOptions()
	generator := NewDiscoveryResponseGenerator(
		options,
		validators_impl.NewExtensionGrantValidator(nil, slog.Default()),
		cibaDiscoveryKeys{},
		validators_impl.NewNotSupportedResourceOwnerPasswordValidator(slog.Default()),
		resources,
		validators_impl.NewSecretParser(nil, slog.Default()),
		slog.Default(),
	)
	doc, err := generator.CreateDiscoveryDocument(context.Background(), "https://wicket.test", "https://wicket.test")
	if err != nil {
		t.Fatalf("create discovery: %v", err)
	}
	if got := doc[gois.DiscoveryBackchannelAuthenticationEndpoint]; got != "https://wicket.test/connect/ciba" {
		t.Fatalf("backchannel endpoint = %v", got)
	}
	if !containsString(doc[gois.DiscoveryGrantTypesSupported].([]string), gois.GrantTypeBackchannelAuthentication) {
		t.Fatalf("grant types missing %q: %#v", gois.GrantTypeBackchannelAuthentication, doc[gois.DiscoveryGrantTypesSupported])
	}
	if got := doc[gois.DiscoveryBackchannelTokenDeliveryModesSupported].([]string); len(got) != 1 || got[0] != gois.BackchannelTokenDeliveryModesPoll {
		t.Fatalf("delivery modes = %#v", got)
	}
	if got := doc[gois.DiscoveryBackchannelUserCodeParameterSupported]; got != true {
		t.Fatalf("user code metadata = %#v", got)
	}
}

func newDiscoveryTestOptions() *config_options.WicketOptions {
	options := config_options.NewWicketOptions()
	options.Discovery.ShowKeySet = false
	options.Discovery.ShowClaims = false
	options.Discovery.ShowIdentityScopes = false
	options.Discovery.ShowApiScopes = false
	options.Discovery.ShowResponseTypes = false
	options.Discovery.ShowResponseModes = false
	options.Discovery.ShowTokenEndpointAuthenticationMethods = false
	return options
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
