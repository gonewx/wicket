// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package authorize

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"testing"
	"time"

	"github.com/gonewx/wicket"
	claimspkg "github.com/gonewx/wicket/claims"
	config_options "github.com/gonewx/wicket/config/options"
	services_impl "github.com/gonewx/wicket/services/impl"
	storage_impl "github.com/gonewx/wicket/storage/impl"
	"github.com/gonewx/wicket/storage/memory"
	storage_models "github.com/gonewx/wicket/storage/models"
	validators_impl "github.com/gonewx/wicket/validators/impl"
	validators_models "github.com/gonewx/wicket/validators/models"
)

const (
	resourceOrders   = "https://resources.example.com/orders"
	resourcePayments = "https://resources.example.com/payments"
)

type resourceClock struct {
	now time.Time
}

func (c *resourceClock) Now() time.Time {
	return c.now
}

func TestNo_resource_indicator_on_code_exchange_should_succeed(t *testing.T) {
	t.Parallel()

	result := validateCodeExchange(t, nil, "")
	if result.Error != nil {
		t.Fatalf("code exchange error = %v", result.Error)
	}
}

func TestNo_resource_indicator_on_authz_endpoint_should_succeed(t *testing.T) {
	t.Parallel()

	result := validateAuthorize(t, gois.ResponseTypesCode, nil)
	if result.Error != nil {
		t.Fatalf("authorize error = %v", result.Error)
	}
}

func TestNo_token_endpoint_resource_indicator_on_code_exchange_should_succeed(t *testing.T) {
	t.Parallel()

	result := validateCodeExchange(t, []string{resourceOrders}, "")
	if result.Error != nil {
		t.Fatalf("code exchange error = %v", result.Error)
	}
}

func TestResource_indicator_on_code_exchange_should_succeed(t *testing.T) {
	t.Parallel()

	result := validateCodeExchange(t, []string{resourceOrders}, resourceOrders)
	if result.Error != nil {
		t.Fatalf("code exchange error = %v", result.Error)
	}
	if result.ValidatedRequest.RequestedResourceGap != resourceOrders {
		t.Fatalf("requested resource = %q, want %q", result.ValidatedRequest.RequestedResourceGap, resourceOrders)
	}
}

func TestResource_indicator_on_refresh_token_exchange_should_succeed(t *testing.T) {
	t.Parallel()

	result := validateRefreshExchange(t, []string{resourceOrders, resourcePayments}, resourcePayments)
	if result.Error != nil {
		t.Fatalf("refresh exchange error = %v", result.Error)
	}
	if result.ValidatedRequest.RequestedResourceGap != resourcePayments {
		t.Fatalf("requested resource = %q, want %q", result.ValidatedRequest.RequestedResourceGap, resourcePayments)
	}
}

func TestNo_resource_indicator_on_refresh_token_exchange_should_succeed(t *testing.T) {
	t.Parallel()

	result := validateRefreshExchange(t, []string{resourceOrders}, "")
	if result.Error != nil {
		t.Fatalf("refresh exchange error = %v", result.Error)
	}
}

func TestResource_indicator_without_offline_access_should_succeed(t *testing.T) {
	t.Parallel()

	result := validateCodeExchange(t, []string{resourceOrders}, resourceOrders)
	if result.Error != nil {
		t.Fatalf("code exchange error = %v", result.Error)
	}
}

func TestIplicit_flow_with_resource_indicator_should_fail(t *testing.T) {
	t.Parallel()

	result := validateAuthorize(t, gois.ResponseTypesToken, []string{resourceOrders})
	if !errors.Is(result.Error, gois.AuthorizeErrorsInvalidTarget) {
		t.Fatalf("authorize error = %v, want %v", result.Error, gois.AuthorizeErrorsInvalidTarget)
	}
}

func validateAuthorize(t *testing.T, responseType string, resources []string) *validators_models.AuthorizeRequestValidationResult {
	t.Helper()

	options := config_options.NewWicketOptions()
	options.Endpoints.EnableCheckSessionEndpoint = false
	client := resourceClient(t)
	if responseType == gois.ResponseTypesToken {
		client.AllowAccessTokensViaBrowser = true
		if err := client.SetAllowedGrantTypes(gois.GrantTypesImplicit); err != nil {
			t.Fatalf("set grant types: %v", err)
		}
	} else if err := client.SetAllowedGrantTypes(gois.GrantTypesCode); err != nil {
		t.Fatalf("set grant types: %v", err)
	}
	clientStore, err := memory.NewMemoryClientStore([]*storage_models.Client{client})
	if err != nil {
		t.Fatalf("client store: %v", err)
	}
	resourceStore := resourceStore(t)
	validator := validators_impl.NewAuthorizeRequestValidator(
		slog.Default(),
		options,
		services_impl.NewIssuerNameService(options),
		clientStore,
		nil,
		nil,
		validators_impl.NewStrictRedirectUriValidator(),
		validators_impl.NewResourceValidator(resourceStore, validators_impl.NewScopeParser(), slog.Default()),
		nil,
		validators_impl.NewCustomAuthorizeRequestValidator(),
	)
	values := url.Values{
		gois.AuthorizeRequestClientId:     {client.ClientId},
		gois.AuthorizeRequestRedirectUri:  {client.RedirectUris[0]},
		gois.AuthorizeRequestResponseType: {responseType},
		gois.AuthorizeRequestScope:        {"orders.read"},
	}
	for _, resource := range resources {
		values.Add(gois.AuthorizeRequestResource, resource)
	}
	return validator.Validate(context.Background(), values, claimspkg.ClaimsPrincipalAnonymous())
}

func validateCodeExchange(t *testing.T, authorizeResources []string, tokenResource string) *validators_models.TokenRequestValidationResult {
	t.Helper()

	client := resourceClient(t)
	codeStore := storage_impl.NewAuthorizationCodeStore()
	refreshStore := storage_impl.NewRefreshTokenStore()
	clock := &resourceClock{now: time.Date(2026, 7, 8, 9, 0, 0, 0, time.UTC)}
	code := storage_models.NewAuthorizationCode()
	code.ClientId = client.ClientId
	code.CreationTime = clock.now
	code.Lifetime = 300
	code.RedirectUri = client.RedirectUris[0]
	code.RequestedScopes = []string{"orders.read"}
	code.RequestedResourceGaps = authorizeResources
	handle, err := codeStore.StoreAuthorizationCode(context.Background(), code)
	if err != nil {
		t.Fatalf("store code: %v", err)
	}
	values := url.Values{
		gois.TokenRequestGrantType:   {gois.GrantTypeAuthorizationCode},
		gois.TokenRequestCode:        {handle},
		gois.TokenRequestRedirectUri: {code.RedirectUri},
	}
	if tokenResource != "" {
		values.Set(gois.TokenRequestResource, tokenResource)
	}
	result, err := tokenValidator(t, client, codeStore, refreshStore, clock).ValidateRequest(context.Background(), values, &validators_models.ClientSecretValidationResult{Client: client})
	if err != nil {
		t.Fatalf("validate token request: %v", err)
	}
	return result
}

func validateRefreshExchange(t *testing.T, authorizedResources []string, tokenResource string) *validators_models.TokenRequestValidationResult {
	t.Helper()

	client := resourceClient(t)
	codeStore := storage_impl.NewAuthorizationCodeStore()
	refreshStore := storage_impl.NewRefreshTokenStore()
	clock := &resourceClock{now: time.Date(2026, 7, 8, 9, 0, 0, 0, time.UTC)}
	refresh := storage_models.NewRefreshToken()
	refresh.AuthorizedScopes = []string{"orders.read", "payments.read"}
	refresh.AuthorizedResourceGaps = authorizedResources
	handle, err := refreshStore.StoreRefreshToken(context.Background(), refresh)
	if err != nil {
		t.Fatalf("store refresh token: %v", err)
	}
	values := url.Values{
		gois.TokenRequestGrantType:    {gois.GrantTypeRefreshToken},
		gois.TokenRequestRefreshToken: {handle},
	}
	if tokenResource != "" {
		values.Set(gois.TokenRequestResource, tokenResource)
	}
	result, err := tokenValidator(t, client, codeStore, refreshStore, clock).ValidateRequest(context.Background(), values, &validators_models.ClientSecretValidationResult{Client: client})
	if err != nil {
		t.Fatalf("validate token request: %v", err)
	}
	return result
}

func tokenValidator(
	t *testing.T,
	client *storage_models.Client,
	codeStore *storage_impl.AuthorizationCodeStore,
	refreshStore *storage_impl.RefreshTokenStore,
	clock *resourceClock,
) *validators_impl.TokenRequestValidator {
	t.Helper()

	options := config_options.NewWicketOptions()
	resourceStore := resourceStore(t)
	backchannelStore := memory.NewMemoryBackchannelAuthenticationRequestStore()
	return validators_impl.NewTokenRequestValidator(
		options,
		services_impl.NewIssuerNameService(options),
		codeStore,
		validators_impl.NewExtensionGrantValidator(nil, slog.Default()),
		validators_impl.NewCustomTokenRequestValidator(),
		validators_impl.NewResourceValidator(resourceStore, validators_impl.NewScopeParser(), slog.Default()),
		resourceStore,
		services_impl.NewRefreshTokenService(refreshStore),
		validators_impl.NewNotSupportedResourceOwnerPasswordValidator(slog.Default()),
		services_impl.NewProfileService(slog.Default()),
		nil,
		validators_impl.NewBackchannelAuthenticationRequestIdValidator(
			backchannelStore,
			services_impl.NewBackchannelAuthenticationThrottlingService(options, clock),
			clock,
		),
		clock,
		slog.Default(),
	)
}

func resourceClient(t *testing.T) *storage_models.Client {
	t.Helper()

	client := storage_models.NewClient()
	client.ClientId = "client"
	client.RequireClientSecret = false
	client.RequirePkce = false
	client.RedirectUris = []string{"https://client.example.com/callback"}
	client.AllowOfflineAccess = true
	client.AllowedScopes = []string{"orders.read", "payments.read", gois.StandardScopesOfflineAccess}
	if err := client.SetAllowedGrantTypes([]string{
		gois.GrantTypeAuthorizationCode,
		gois.GrantTypeRefreshToken,
	}); err != nil {
		t.Fatalf("set grant types: %v", err)
	}
	return client
}

func resourceStore(t *testing.T) *memory.MemoryResourcesStore {
	t.Helper()

	ordersScope := storage_models.NewApiScope()
	ordersScope.Name = "orders.read"
	paymentsScope := storage_models.NewApiScope()
	paymentsScope.Name = "payments.read"
	orders := storage_models.NewApiResource()
	orders.Name = resourceOrders
	orders.Scopes = []string{ordersScope.Name}
	orders.RequireResourceGap = true
	payments := storage_models.NewApiResource()
	payments.Name = resourcePayments
	payments.Scopes = []string{paymentsScope.Name}
	payments.RequireResourceGap = true
	store, err := memory.NewMemoryResourcesStore(nil, []*storage_models.ApiResource{orders, payments}, []*storage_models.ApiScope{ordersScope, paymentsScope})
	if err != nil {
		t.Fatalf("resource store: %v", err)
	}
	return store
}
