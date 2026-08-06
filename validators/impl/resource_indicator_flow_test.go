// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/gonewx/wicket"
	claimspkg "github.com/gonewx/wicket/claims"
	config_options "github.com/gonewx/wicket/config/options"
	services_impl "github.com/gonewx/wicket/services/impl"
	storage_impl "github.com/gonewx/wicket/storage/impl"
	"github.com/gonewx/wicket/storage/memory"
	storage_models "github.com/gonewx/wicket/storage/models"
	validators_models "github.com/gonewx/wicket/validators/models"
)

func TestAuthorizeRequestValidatorResourceIndicatorTable(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		grantTypes       []string
		responseType     string
		allowBrowser     bool
		resources        []string
		wantErr          error
		wantApiResources []string
	}{
		"code flow binds requested resource": {
			grantTypes:       gois.GrantTypesCode,
			responseType:     gois.ResponseTypesCode,
			resources:        []string{resourceOrders},
			wantApiResources: []string{resourceOrders},
		},
		"malformed resource returns invalid target": {
			grantTypes:   gois.GrantTypesCode,
			responseType: gois.ResponseTypesCode,
			resources:    []string{resourceOrders + "#frag"},
			wantErr:      gois.AuthorizeErrorsInvalidTarget,
		},
		"empty resource returns invalid target": {
			grantTypes:   gois.GrantTypesCode,
			responseType: gois.ResponseTypesCode,
			resources:    []string{""},
			wantErr:      gois.AuthorizeErrorsInvalidTarget,
		},
		"implicit token response with resource remains rejected": {
			grantTypes:   gois.GrantTypesImplicit,
			responseType: gois.ResponseTypesToken,
			allowBrowser: true,
			resources:    []string{resourceOrders},
			wantErr:      gois.AuthorizeErrorsInvalidTarget,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			validator, client := newResourceAuthorizeValidator(t, tt.grantTypes)
			client.AllowAccessTokensViaBrowser = tt.allowBrowser
			values := url.Values{
				gois.AuthorizeRequestClientId:     {client.ClientId},
				gois.AuthorizeRequestRedirectUri:  {client.RedirectUris[0]},
				gois.AuthorizeRequestResponseType: {tt.responseType},
				gois.AuthorizeRequestScope:        {"orders.read"},
			}
			for _, resource := range tt.resources {
				values.Add(gois.AuthorizeRequestResource, resource)
			}

			result := validator.Validate(context.Background(), values, claimspkg.ClaimsPrincipalAnonymous())
			if !errors.Is(result.Error, tt.wantErr) {
				t.Fatalf("error = %v, want %v", result.Error, tt.wantErr)
			}
			if tt.wantErr != nil {
				return
			}
			if !reflect.DeepEqual(result.ValidatedRequest.RequestedResourceIndiators, tt.resources) {
				t.Fatalf("RequestedResourceIndiators = %v, want %v", result.ValidatedRequest.RequestedResourceIndiators, tt.resources)
			}
			if got := sortedStrings(apiResourceNames(result.ValidatedRequest.ValidatedResources.Resources.ApiResources())); !reflect.DeepEqual(got, sortedStrings(tt.wantApiResources)) {
				t.Fatalf("ApiResources = %v, want %v", got, sortedStrings(tt.wantApiResources))
			}
		})
	}
}

func TestTokenRequestValidatorResourceIndicatorTable(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		setup             func(t *testing.T, ctx *resourceTokenValidatorContext) url.Values
		wantErr           error
		wantRequested     string
		wantEffective     []string
		wantApiResources  []string
		wantResourceGaps  []string
		wantRefreshHandle bool
	}{
		"authorization code accepts original resource subset": {
			setup: func(t *testing.T, ctx *resourceTokenValidatorContext) url.Values {
				code := storage_models.NewAuthorizationCode()
				code.ClientId = ctx.client.ClientId
				code.CreationTime = ctx.clock.now
				code.Lifetime = 300
				code.RedirectUri = "https://client.example.com/callback"
				code.RequestedScopes = []string{"orders.read"}
				code.RequestedResourceGaps = []string{resourceOrders}
				handle := "resource-code"
				if err := ctx.authorizationCodes.StoreAuthorizationCode(context.Background(), handle, code); err != nil {
					t.Fatalf("store code: %v", err)
				}
				return url.Values{
					gois.TokenRequestGrantType:   {gois.GrantTypeAuthorizationCode},
					gois.TokenRequestCode:        {handle},
					gois.TokenRequestRedirectUri: {code.RedirectUri},
					gois.TokenRequestResource:    {resourceOrders},
				}
			},
			wantRequested:    resourceOrders,
			wantEffective:    []string{"orders.read"},
			wantApiResources: []string{resourceOrders},
		},
		"authorization code without token resource returns default resource scope": {
			setup: func(t *testing.T, ctx *resourceTokenValidatorContext) url.Values {
				code := storage_models.NewAuthorizationCode()
				code.ClientId = ctx.client.ClientId
				code.CreationTime = ctx.clock.now
				code.Lifetime = 300
				code.RedirectUri = "https://client.example.com/callback"
				code.RequestedScopes = []string{"orders.read", "common.read", gois.StandardScopesOfflineAccess}
				code.RequestedResourceGaps = []string{resourceOrders}
				handle := "resource-code"
				if err := ctx.authorizationCodes.StoreAuthorizationCode(context.Background(), handle, code); err != nil {
					t.Fatalf("store code: %v", err)
				}
				return url.Values{
					gois.TokenRequestGrantType:   {gois.GrantTypeAuthorizationCode},
					gois.TokenRequestCode:        {handle},
					gois.TokenRequestRedirectUri: {code.RedirectUri},
				}
			},
			wantEffective:    []string{"common.read", gois.StandardScopesOfflineAccess},
			wantApiResources: []string{resourceCommon},
		},
		"authorization code rejects resource outside original grant": {
			setup: func(t *testing.T, ctx *resourceTokenValidatorContext) url.Values {
				code := storage_models.NewAuthorizationCode()
				code.ClientId = ctx.client.ClientId
				code.CreationTime = ctx.clock.now
				code.Lifetime = 300
				code.RedirectUri = "https://client.example.com/callback"
				code.RequestedScopes = []string{"orders.read"}
				code.RequestedResourceGaps = []string{resourceOrders}
				handle := "resource-code"
				if err := ctx.authorizationCodes.StoreAuthorizationCode(context.Background(), handle, code); err != nil {
					t.Fatalf("store code: %v", err)
				}
				return url.Values{
					gois.TokenRequestGrantType:   {gois.GrantTypeAuthorizationCode},
					gois.TokenRequestCode:        {handle},
					gois.TokenRequestRedirectUri: {code.RedirectUri},
					gois.TokenRequestResource:    {resourcePayments},
				}
			},
			wantErr: gois.TokenErrorsInvalidTarget,
		},
		"authorization code rejects resource when original grant had none": {
			setup: func(t *testing.T, ctx *resourceTokenValidatorContext) url.Values {
				code := storage_models.NewAuthorizationCode()
				code.ClientId = ctx.client.ClientId
				code.CreationTime = ctx.clock.now
				code.Lifetime = 300
				code.RedirectUri = "https://client.example.com/callback"
				code.RequestedScopes = []string{"orders.read"}
				handle := "resource-code"
				if err := ctx.authorizationCodes.StoreAuthorizationCode(context.Background(), handle, code); err != nil {
					t.Fatalf("store code: %v", err)
				}
				return url.Values{
					gois.TokenRequestGrantType:   {gois.GrantTypeAuthorizationCode},
					gois.TokenRequestCode:        {handle},
					gois.TokenRequestRedirectUri: {code.RedirectUri},
					gois.TokenRequestResource:    {resourceOrders},
				}
			},
			wantErr: gois.TokenErrorsInvalidTarget,
		},
		"token endpoint rejects multiple resources": {
			setup: func(t *testing.T, ctx *resourceTokenValidatorContext) url.Values {
				return url.Values{
					gois.TokenRequestGrantType: {gois.GrantTypeClientCredentials},
					gois.TokenRequestScope:     {"orders.read"},
					gois.TokenRequestResource:  {resourceOrders, resourcePayments},
				}
			},
			wantErr: gois.TokenErrorsInvalidTarget,
		},
		"token endpoint rejects empty resource": {
			setup: func(t *testing.T, ctx *resourceTokenValidatorContext) url.Values {
				return url.Values{
					gois.TokenRequestGrantType: {gois.GrantTypeClientCredentials},
					gois.TokenRequestScope:     {"orders.read"},
					gois.TokenRequestResource:  {""},
				}
			},
			wantErr: gois.TokenErrorsInvalidTarget,
		},
		"device code rejects explicit resource": {
			setup: func(t *testing.T, ctx *resourceTokenValidatorContext) url.Values {
				return url.Values{
					gois.TokenRequestGrantType:  {gois.GrantTypeDeviceCode},
					gois.TokenRequestDeviceCode: {"device"},
					gois.TokenRequestResource:   {resourceOrders},
				}
			},
			wantErr: gois.TokenErrorsInvalidTarget,
		},
		"refresh token accepts authorized resource subset": {
			setup: func(t *testing.T, ctx *resourceTokenValidatorContext) url.Values {
				refresh := storage_models.NewRefreshToken()
				refresh.AuthorizedScopes = []string{"orders.read", "payments.read"}
				refresh.AuthorizedResourceGaps = []string{resourceOrders, resourcePayments}
				handle := "resource-refresh"
				if err := ctx.refreshTokens.StoreRefreshToken(context.Background(), handle, refresh); err != nil {
					t.Fatalf("store refresh token: %v", err)
				}
				return url.Values{
					gois.TokenRequestGrantType:    {gois.GrantTypeRefreshToken},
					gois.TokenRequestRefreshToken: {handle},
					gois.TokenRequestResource:     {resourcePayments},
				}
			},
			wantRequested:     resourcePayments,
			wantEffective:     []string{"payments.read"},
			wantApiResources:  []string{resourcePayments},
			wantRefreshHandle: true,
		},
		"refresh token rejects resource when original grant had none": {
			setup: func(t *testing.T, ctx *resourceTokenValidatorContext) url.Values {
				refresh := storage_models.NewRefreshToken()
				refresh.AuthorizedScopes = []string{"orders.read"}
				refresh.AuthorizedResourceGaps = []string{}
				handle := "resource-refresh"
				if err := ctx.refreshTokens.StoreRefreshToken(context.Background(), handle, refresh); err != nil {
					t.Fatalf("store refresh token: %v", err)
				}
				return url.Values{
					gois.TokenRequestGrantType:    {gois.GrantTypeRefreshToken},
					gois.TokenRequestRefreshToken: {handle},
					gois.TokenRequestResource:     {resourceOrders},
				}
			},
			wantErr: gois.TokenErrorsInvalidTarget,
		},
		"CIBA grant reuses saved requested resources": {
			setup: func(t *testing.T, ctx *resourceTokenValidatorContext) url.Values {
				state := &storage_models.BackchannelAuthenticationRequest{
					RequestId:             "req",
					ClientId:              ctx.client.ClientId,
					Status:                storage_models.BackchannelAuthenticationRequestStatusApproved,
					ExpirationTime:        ctx.clock.now.Add(time.Minute),
					RequestedScopes:       []string{"orders.read"},
					RequestedResourceGaps: []string{resourceOrders},
				}
				if err := ctx.backchannelRequests.StoreBackchannelAuthenticationRequest(context.Background(), state.RequestId, state); err != nil {
					t.Fatalf("store CIBA request: %v", err)
				}
				return url.Values{
					gois.TokenRequestGrantType:               {gois.GrantTypeBackchannelAuthentication},
					gois.TokenRequestAuthenticationRequestId: {state.RequestId},
				}
			},
			wantRequested:    resourceOrders,
			wantEffective:    []string{"orders.read"},
			wantApiResources: []string{resourceOrders},
		},
		"CIBA grant rejects resource when saved request had none": {
			setup: func(t *testing.T, ctx *resourceTokenValidatorContext) url.Values {
				state := &storage_models.BackchannelAuthenticationRequest{
					RequestId:      "req",
					ClientId:       ctx.client.ClientId,
					Status:         storage_models.BackchannelAuthenticationRequestStatusApproved,
					ExpirationTime: ctx.clock.now.Add(time.Minute),
					RequestedScopes: []string{
						"orders.read",
					},
				}
				if err := ctx.backchannelRequests.StoreBackchannelAuthenticationRequest(context.Background(), state.RequestId, state); err != nil {
					t.Fatalf("store CIBA request: %v", err)
				}
				return url.Values{
					gois.TokenRequestGrantType:               {gois.GrantTypeBackchannelAuthentication},
					gois.TokenRequestAuthenticationRequestId: {state.RequestId},
					gois.TokenRequestResource:                {resourceOrders},
				}
			},
			wantErr: gois.TokenErrorsInvalidTarget,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctx := newResourceTokenValidatorContext(t)
			parameters := tt.setup(t, ctx)
			result, err := ctx.validator.ValidateRequest(context.Background(), parameters, &validators_models.ClientSecretValidationResult{Client: ctx.client})
			if err != nil {
				t.Fatalf("validate token request: %v", err)
			}
			if !errors.Is(result.Error, tt.wantErr) {
				t.Fatalf("error = %v, want %v", result.Error, tt.wantErr)
			}
			if tt.wantErr != nil {
				return
			}
			if result.ValidatedRequest.RequestedResourceGap != tt.wantRequested {
				t.Fatalf("RequestedResourceGap = %q, want %q", result.ValidatedRequest.RequestedResourceGap, tt.wantRequested)
			}
			if got := sortedStrings(result.ValidatedRequest.ValidatedResources.RawScopeValues()); !reflect.DeepEqual(got, sortedStrings(tt.wantEffective)) {
				t.Fatalf("RawScopeValues = %v, want %v", got, sortedStrings(tt.wantEffective))
			}
			if got := sortedStrings(apiResourceNames(result.ValidatedRequest.ValidatedResources.Resources.ApiResources())); !reflect.DeepEqual(got, sortedStrings(tt.wantApiResources)) {
				t.Fatalf("ApiResources = %v, want %v", got, sortedStrings(tt.wantApiResources))
			}
			if tt.wantRefreshHandle && result.ValidatedRequest.RefreshTokenHandle == "" {
				t.Fatal("missing refresh token handle")
			}
			if tt.wantResourceGaps != nil && !reflect.DeepEqual(result.ValidatedRequest.AuthorizationCode.RequestedResourceGaps, tt.wantResourceGaps) {
				t.Fatalf("RequestedResourceGaps = %v, want %v", result.ValidatedRequest.AuthorizationCode.RequestedResourceGaps, tt.wantResourceGaps)
			}
		})
	}
}

func TestBackchannelAuthenticationRequestValidatorStoresRequestedResources(t *testing.T) {
	t.Parallel()

	options := config_options.NewWicketOptions()
	store := memory.NewMemoryBackchannelAuthenticationRequestStore()
	resourceStore := newResourceValidatorStore(t)
	validator := NewBackchannelAuthenticationRequestValidator(
		options,
		store,
		NewResourceValidator(resourceStore, NewScopeParser(), slog.Default()),
		NewBackchannelAuthenticationUserValidator(),
		services_impl.NewBackchannelAuthenticationNotificationService(nil),
		&cibaTestClock{now: time.Date(2026, 7, 8, 9, 0, 0, 0, time.UTC)},
		slog.Default(),
	)
	client := newResourceTokenClient(t)
	if err := client.SetAllowedGrantTypes(gois.GrantTypesBackchannelAuthentication); err != nil {
		t.Fatalf("set grant types: %v", err)
	}

	result := validator.Validate(context.Background(), url.Values{
		gois.BackchannelAuthenticationRequestScope:     {"orders.read"},
		gois.BackchannelAuthenticationRequestResource:  {resourceOrders},
		gois.BackchannelAuthenticationRequestLoginHint: {"alice"},
	}, client)
	if result.Error != nil {
		t.Fatalf("Validate error: %v", result.Error)
	}
	if !reflect.DeepEqual(result.Request.RequestedResourceGaps, []string{resourceOrders}) {
		t.Fatalf("RequestedResourceGaps = %v, want %v", result.Request.RequestedResourceGaps, []string{resourceOrders})
	}
}

func TestBackchannelAuthenticationRequestValidatorRejectsEmptyResource(t *testing.T) {
	t.Parallel()

	options := config_options.NewWicketOptions()
	store := memory.NewMemoryBackchannelAuthenticationRequestStore()
	resourceStore := newResourceValidatorStore(t)
	validator := NewBackchannelAuthenticationRequestValidator(
		options,
		store,
		NewResourceValidator(resourceStore, NewScopeParser(), slog.Default()),
		NewBackchannelAuthenticationUserValidator(),
		services_impl.NewBackchannelAuthenticationNotificationService(nil),
		&cibaTestClock{now: time.Date(2026, 7, 8, 9, 0, 0, 0, time.UTC)},
		slog.Default(),
	)
	client := newResourceTokenClient(t)
	if err := client.SetAllowedGrantTypes(gois.GrantTypesBackchannelAuthentication); err != nil {
		t.Fatalf("set grant types: %v", err)
	}

	result := validator.Validate(context.Background(), url.Values{
		gois.BackchannelAuthenticationRequestScope:     {"orders.read"},
		gois.BackchannelAuthenticationRequestResource:  {""},
		gois.BackchannelAuthenticationRequestLoginHint: {"alice"},
	}, client)
	if !errors.Is(result.Error, gois.TokenErrorsInvalidTarget) {
		t.Fatalf("Validate error = %v, want %v", result.Error, gois.TokenErrorsInvalidTarget)
	}
}

type resourceTokenValidatorContext struct {
	validator           *TokenRequestValidator
	client              *storage_models.Client
	authorizationCodes  *storage_impl.AuthorizationCodeStore
	refreshTokens       *storage_impl.RefreshTokenStore
	backchannelRequests *memory.MemoryBackchannelAuthenticationRequestStore
	clock               *cibaTestClock
}

func newResourceAuthorizeValidator(t *testing.T, grantTypes []string) (*AuthorizeRequestValidator, *storage_models.Client) {
	t.Helper()

	options := config_options.NewWicketOptions()
	options.Endpoints.EnableCheckSessionEndpoint = false
	client := newResourceTokenClient(t)
	client.RedirectUris = []string{"https://client.example.com/callback"}
	client.RequirePkce = false
	if err := client.SetAllowedGrantTypes(grantTypes); err != nil {
		t.Fatalf("set grant types: %v", err)
	}
	clientStore, err := memory.NewMemoryClientStore([]*storage_models.Client{client})
	if err != nil {
		t.Fatalf("client store: %v", err)
	}
	resourceStore := newResourceValidatorStore(t)

	return NewAuthorizeRequestValidator(
		slog.Default(),
		options,
		services_impl.NewIssuerNameService(options),
		clientStore,
		nil,
		nil,
		NewStrictRedirectUriValidator(),
		NewResourceValidator(resourceStore, NewScopeParser(), slog.Default()),
		nil,
		NewCustomAuthorizeRequestValidator(),
	), client
}

func newResourceTokenValidatorContext(t *testing.T) *resourceTokenValidatorContext {
	t.Helper()

	options := config_options.NewWicketOptions()
	clock := &cibaTestClock{now: time.Date(2026, 7, 8, 9, 0, 0, 0, time.UTC)}
	client := newResourceTokenClient(t)
	if err := client.SetAllowedGrantTypes([]string{
		gois.GrantTypeAuthorizationCode,
		gois.GrantTypeClientCredentials,
		gois.GrantTypeRefreshToken,
		gois.GrantTypeBackchannelAuthentication,
	}); err != nil {
		t.Fatalf("set grant types: %v", err)
	}
	resourceStore := newResourceValidatorStore(t)
	authorizationCodes := storage_impl.NewAuthorizationCodeStore()
	refreshTokens := storage_impl.NewRefreshTokenStore()
	backchannelRequests := memory.NewMemoryBackchannelAuthenticationRequestStore()
	refreshService := services_impl.NewRefreshTokenService(refreshTokens, services_impl.NewHandleGenerationService())

	return &resourceTokenValidatorContext{
		client:              client,
		authorizationCodes:  authorizationCodes,
		refreshTokens:       refreshTokens,
		backchannelRequests: backchannelRequests,
		clock:               clock,
		validator: NewTokenRequestValidator(
			options,
			services_impl.NewIssuerNameService(options),
			authorizationCodes,
			NewExtensionGrantValidator(nil, slog.Default()),
			NewCustomTokenRequestValidator(),
			NewResourceValidator(resourceStore, NewScopeParser(), slog.Default()),
			resourceStore,
			refreshService,
			NewNotSupportedResourceOwnerPasswordValidator(slog.Default()),
			services_impl.NewProfileService(slog.Default()),
			nil,
			NewBackchannelAuthenticationRequestIdValidator(
				backchannelRequests,
				services_impl.NewBackchannelAuthenticationThrottlingService(options, clock),
				clock,
			),
			clock,
			slog.Default(),
		),
	}
}

func newResourceTokenClient(t *testing.T) *storage_models.Client {
	t.Helper()

	client := storage_models.NewClient()
	client.ClientId = "client"
	client.RequireClientSecret = false
	client.RequirePkce = false
	client.AllowOfflineAccess = true
	client.AllowedScopes = []string{"orders.read", "payments.read", "common.read", gois.StandardScopesOfflineAccess}
	return client
}
