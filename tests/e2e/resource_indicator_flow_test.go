// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package e2e_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gonewx/wicket"
	claimspkg "github.com/gonewx/wicket/claims"
	config_options "github.com/gonewx/wicket/config/options"
	responses_impl "github.com/gonewx/wicket/responses/impl"
	services_impl "github.com/gonewx/wicket/services/impl"
	storage_impl "github.com/gonewx/wicket/storage/impl"
	"github.com/gonewx/wicket/storage/memory"
	storage_models "github.com/gonewx/wicket/storage/models"
	validators_impl "github.com/gonewx/wicket/validators/impl"
	validators_models "github.com/gonewx/wicket/validators/models"
)

const (
	resourceIndicatorOrders   = "https://resources.example.com/orders"
	resourceIndicatorPayments = "https://resources.example.com/payments"
)

type resourceIndicatorE2EClock struct {
	now time.Time
}

func (c *resourceIndicatorE2EClock) Now() time.Time {
	return c.now
}

type resourceIndicatorTokenRecorder struct {
	tokens []*storage_models.Token
}

func (r *resourceIndicatorTokenRecorder) CreateToken(ctx context.Context, token *storage_models.Token) (string, error) {
	r.tokens = append(r.tokens, token)
	return fmt.Sprintf("token-%d", len(r.tokens)), nil
}

type resourceIndicatorE2EFixture struct {
	authorizeValidator *validators_impl.AuthorizeRequestValidator
	tokenValidator     *validators_impl.TokenRequestValidator
	tokenGenerator     *responses_impl.TokenResponseGenerator
	authorizationCodes *storage_impl.AuthorizationCodeStore
	refreshTokens      *storage_impl.RefreshTokenStore
	recorder           *resourceIndicatorTokenRecorder
	client             *storage_models.Client
	clock              *resourceIndicatorE2EClock
}

func TestResourceIndicatorAuthorizationCodeRefreshFlowE2E(t *testing.T) {
	t.Parallel()

	fixture := newResourceIndicatorE2EFixture(t)
	authorizeResult := fixture.validateAuthorize(t, gois.ResponseTypesCode, []string{resourceIndicatorOrders, resourceIndicatorPayments})
	if authorizeResult.Error != nil {
		t.Fatalf("authorize error = %v", authorizeResult.Error)
	}

	codeHandle := fixture.storeAuthorizationCode(t, authorizeResult.ValidatedRequest)
	tokenResult := fixture.validateAuthorizationCodeToken(t, codeHandle, resourceIndicatorOrders)
	if tokenResult.Error != nil {
		t.Fatalf("authorization code token error = %v", tokenResult.Error)
	}

	tokenResponse, err := fixture.tokenGenerator.Handle(context.Background(), tokenResult)
	if err != nil {
		t.Fatalf("authorization code token response: %v", err)
	}
	assertSameStrings(t, strings.Fields(tokenResponse.Scope), []string{"orders.read", gois.StandardScopesOfflineAccess})
	assertLastAccessTokenAudience(t, fixture.recorder, []string{resourceIndicatorOrders})
	if tokenResponse.RefreshToken == "" {
		t.Fatal("missing refresh token")
	}

	refreshToken, err := fixture.refreshTokens.GetRefreshToken(context.Background(), tokenResponse.RefreshToken)
	if err != nil {
		t.Fatalf("get refresh token: %v", err)
	}
	if refreshToken == nil {
		t.Fatal("stored refresh token is nil")
	}
	assertSameStrings(t, refreshToken.AuthorizedResourceGaps, []string{resourceIndicatorOrders, resourceIndicatorPayments})
	if refreshToken.GetAccessToken(resourceIndicatorOrders) == nil {
		t.Fatal("orders access token was not stored under the selected resource")
	}
	if refreshToken.GetAccessToken(resourceIndicatorPayments) != nil {
		t.Fatal("payments access token exists before payments refresh exchange")
	}

	refreshResult := fixture.validateRefreshToken(t, tokenResponse.RefreshToken, resourceIndicatorPayments)
	if refreshResult.Error != nil {
		t.Fatalf("refresh token error = %v", refreshResult.Error)
	}
	refreshResponse, err := fixture.tokenGenerator.Handle(context.Background(), refreshResult)
	if err != nil {
		t.Fatalf("refresh token response: %v", err)
	}
	if refreshResponse.RefreshToken != tokenResponse.RefreshToken {
		t.Fatalf("refresh handle = %q, want %q", refreshResponse.RefreshToken, tokenResponse.RefreshToken)
	}
	assertSameStrings(t, strings.Fields(refreshResponse.Scope), []string{"payments.read", gois.StandardScopesOfflineAccess})
	assertLastAccessTokenAudience(t, fixture.recorder, []string{resourceIndicatorPayments})

	updatedRefreshToken, err := fixture.refreshTokens.GetRefreshToken(context.Background(), refreshResponse.RefreshToken)
	if err != nil {
		t.Fatalf("get updated refresh token: %v", err)
	}
	if updatedRefreshToken.GetAccessToken(resourceIndicatorOrders) == nil {
		t.Fatal("orders access token was overwritten")
	}
	if updatedRefreshToken.GetAccessToken(resourceIndicatorPayments) == nil {
		t.Fatal("payments access token was not stored under the selected resource")
	}
}

func TestResourceIndicatorInvalidTargetsE2E(t *testing.T) {
	t.Parallel()

	tests := map[string]func(t *testing.T){
		"authorization endpoint rejects fragmented resource": func(t *testing.T) {
			fixture := newResourceIndicatorE2EFixture(t)
			result := fixture.validateAuthorize(t, gois.ResponseTypesCode, []string{resourceIndicatorOrders + "#fragment"})
			if !errors.Is(result.Error, gois.AuthorizeErrorsInvalidTarget) {
				t.Fatalf("authorize error = %v, want %v", result.Error, gois.AuthorizeErrorsInvalidTarget)
			}
		},
		"authorization endpoint rejects empty resource": func(t *testing.T) {
			fixture := newResourceIndicatorE2EFixture(t)
			result := fixture.validateAuthorize(t, gois.ResponseTypesCode, []string{""})
			if !errors.Is(result.Error, gois.AuthorizeErrorsInvalidTarget) {
				t.Fatalf("authorize error = %v, want %v", result.Error, gois.AuthorizeErrorsInvalidTarget)
			}
		},
		"authorization code exchange rejects resource outside grant": func(t *testing.T) {
			fixture := newResourceIndicatorE2EFixture(t)
			authorizeResult := fixture.validateAuthorize(t, gois.ResponseTypesCode, []string{resourceIndicatorOrders})
			if authorizeResult.Error != nil {
				t.Fatalf("authorize error = %v", authorizeResult.Error)
			}
			codeHandle := fixture.storeAuthorizationCode(t, authorizeResult.ValidatedRequest)
			result := fixture.validateAuthorizationCodeToken(t, codeHandle, resourceIndicatorPayments)
			if !errors.Is(result.Error, gois.TokenErrorsInvalidTarget) {
				t.Fatalf("token error = %v, want %v", result.Error, gois.TokenErrorsInvalidTarget)
			}
		},
		"refresh token exchange rejects resource when original authorization had none": func(t *testing.T) {
			fixture := newResourceIndicatorE2EFixture(t)
			authorizeResult := fixture.validateAuthorize(t, gois.ResponseTypesCode, nil)
			if authorizeResult.Error != nil {
				t.Fatalf("authorize error = %v", authorizeResult.Error)
			}
			codeHandle := fixture.storeAuthorizationCode(t, authorizeResult.ValidatedRequest)
			tokenResult := fixture.validateAuthorizationCodeToken(t, codeHandle, "")
			if tokenResult.Error != nil {
				t.Fatalf("authorization code token error = %v", tokenResult.Error)
			}
			tokenResponse, err := fixture.tokenGenerator.Handle(context.Background(), tokenResult)
			if err != nil {
				t.Fatalf("authorization code token response: %v", err)
			}
			result := fixture.validateRefreshToken(t, tokenResponse.RefreshToken, resourceIndicatorOrders)
			if !errors.Is(result.Error, gois.TokenErrorsInvalidTarget) {
				t.Fatalf("refresh token error = %v, want %v", result.Error, gois.TokenErrorsInvalidTarget)
			}
		},
		"token endpoint rejects multiple resource parameters": func(t *testing.T) {
			fixture := newResourceIndicatorE2EFixture(t)
			result, err := fixture.tokenValidator.ValidateRequest(context.Background(), url.Values{
				gois.TokenRequestGrantType: {gois.GrantTypeAuthorizationCode},
				gois.TokenRequestResource:  {resourceIndicatorOrders, resourceIndicatorPayments},
			}, &validators_models.ClientSecretValidationResult{Client: fixture.client})
			if err != nil {
				t.Fatalf("validate token request: %v", err)
			}
			if !errors.Is(result.Error, gois.TokenErrorsInvalidTarget) {
				t.Fatalf("token error = %v, want %v", result.Error, gois.TokenErrorsInvalidTarget)
			}
		},
		"token endpoint rejects empty resource": func(t *testing.T) {
			fixture := newResourceIndicatorE2EFixture(t)
			result, err := fixture.tokenValidator.ValidateRequest(context.Background(), url.Values{
				gois.TokenRequestGrantType: {gois.GrantTypeAuthorizationCode},
				gois.TokenRequestResource:  {""},
			}, &validators_models.ClientSecretValidationResult{Client: fixture.client})
			if err != nil {
				t.Fatalf("validate token request: %v", err)
			}
			if !errors.Is(result.Error, gois.TokenErrorsInvalidTarget) {
				t.Fatalf("token error = %v, want %v", result.Error, gois.TokenErrorsInvalidTarget)
			}
		},
		"implicit token response rejects resource": func(t *testing.T) {
			fixture := newResourceIndicatorE2EFixture(t)
			fixture.client.AllowAccessTokensViaBrowser = true
			if err := fixture.client.SetAllowedGrantTypes(gois.GrantTypesImplicit); err != nil {
				t.Fatalf("set grant types: %v", err)
			}
			result := fixture.validateAuthorize(t, gois.ResponseTypesToken, []string{resourceIndicatorOrders})
			if !errors.Is(result.Error, gois.AuthorizeErrorsInvalidTarget) {
				t.Fatalf("authorize error = %v, want %v", result.Error, gois.AuthorizeErrorsInvalidTarget)
			}
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			test(t)
		})
	}
}

func newResourceIndicatorE2EFixture(t *testing.T) *resourceIndicatorE2EFixture {
	t.Helper()

	logger := slog.Default()
	options := config_options.NewWicketOptions()
	options.Endpoints.EnableCheckSessionEndpoint = false
	clock := &resourceIndicatorE2EClock{now: time.Date(2026, 7, 8, 9, 0, 0, 0, time.UTC)}
	client := newResourceIndicatorClient(t)
	clientStore, err := memory.NewMemoryClientStore([]*storage_models.Client{client})
	if err != nil {
		t.Fatalf("client store: %v", err)
	}
	resourceStore := newResourceIndicatorStore(t)
	authorizationCodes := storage_impl.NewAuthorizationCodeStore()
	refreshTokens := storage_impl.NewRefreshTokenStore()
	refreshService := services_impl.NewRefreshTokenService(refreshTokens, services_impl.NewHandleGenerationService())
	resourceValidator := validators_impl.NewResourceValidator(resourceStore, validators_impl.NewScopeParser(), logger)
	backchannelRequests := memory.NewMemoryBackchannelAuthenticationRequestStore()
	recorder := &resourceIndicatorTokenRecorder{}
	tokenService := services_impl.NewTokenService(
		services_impl.NewClaimsService(),
		storage_impl.NewReferenceTokenStore(),
		recorder,
		clock,
		nil,
		options,
		logger,
		nil,
	)

	return &resourceIndicatorE2EFixture{
		authorizeValidator: validators_impl.NewAuthorizeRequestValidator(
			logger,
			options,
			services_impl.NewIssuerNameService(options),
			clientStore,
			nil,
			nil,
			validators_impl.NewStrictRedirectUriValidator(),
			resourceValidator,
			nil,
			validators_impl.NewCustomAuthorizeRequestValidator(),
		),
		tokenValidator: validators_impl.NewTokenRequestValidator(
			options,
			services_impl.NewIssuerNameService(options),
			authorizationCodes,
			validators_impl.NewExtensionGrantValidator(nil, logger),
			validators_impl.NewCustomTokenRequestValidator(),
			resourceValidator,
			resourceStore,
			refreshService,
			validators_impl.NewNotSupportedResourceOwnerPasswordValidator(logger),
			services_impl.NewProfileService(logger),
			nil,
			validators_impl.NewBackchannelAuthenticationRequestIdValidator(
				backchannelRequests,
				services_impl.NewBackchannelAuthenticationThrottlingService(options, clock),
				clock,
			),
			clock,
			logger,
		),
		tokenGenerator: responses_impl.NewTokenResponseGenerator(
			clock,
			tokenService,
			refreshService,
			validators_impl.NewScopeParser(),
			resourceStore,
			clientStore,
			logger,
		),
		authorizationCodes: authorizationCodes,
		refreshTokens:      refreshTokens,
		recorder:           recorder,
		client:             client,
		clock:              clock,
	}
}

func newResourceIndicatorClient(t *testing.T) *storage_models.Client {
	t.Helper()

	client := storage_models.NewClient()
	client.ClientId = "resource-indicator-client"
	client.RequireClientSecret = false
	client.RequirePkce = false
	client.RedirectUris = []string{"https://client.example.com/callback"}
	client.AllowOfflineAccess = true
	client.AllowedScopes = []string{"orders.read", "payments.read", gois.StandardScopesOfflineAccess}
	if err := client.SetAllowedGrantTypes([]string{gois.GrantTypeAuthorizationCode, gois.GrantTypeRefreshToken}); err != nil {
		t.Fatalf("set grant types: %v", err)
	}
	return client
}

func newResourceIndicatorStore(t *testing.T) *memory.MemoryResourcesStore {
	t.Helper()

	ordersScope := storage_models.NewApiScope()
	ordersScope.Name = "orders.read"
	paymentsScope := storage_models.NewApiScope()
	paymentsScope.Name = "payments.read"
	orders := storage_models.NewApiResource()
	orders.Name = resourceIndicatorOrders
	orders.Scopes = []string{ordersScope.Name}
	orders.RequireResourceGap = true
	payments := storage_models.NewApiResource()
	payments.Name = resourceIndicatorPayments
	payments.Scopes = []string{paymentsScope.Name}
	payments.RequireResourceGap = true

	store, err := memory.NewMemoryResourcesStore(nil, []*storage_models.ApiResource{orders, payments}, []*storage_models.ApiScope{ordersScope, paymentsScope})
	if err != nil {
		t.Fatalf("resource store: %v", err)
	}
	return store
}

func (f *resourceIndicatorE2EFixture) validateAuthorize(t *testing.T, responseType string, resources []string) *validators_models.AuthorizeRequestValidationResult {
	t.Helper()

	values := url.Values{
		gois.AuthorizeRequestClientId:     {f.client.ClientId},
		gois.AuthorizeRequestRedirectUri:  {f.client.RedirectUris[0]},
		gois.AuthorizeRequestResponseType: {responseType},
		gois.AuthorizeRequestScope:        {"orders.read payments.read " + gois.StandardScopesOfflineAccess},
	}
	for _, resource := range resources {
		values.Add(gois.AuthorizeRequestResource, resource)
	}
	return f.authorizeValidator.Validate(context.Background(), values, claimspkg.ClaimsPrincipalAnonymous())
}

func (f *resourceIndicatorE2EFixture) storeAuthorizationCode(t *testing.T, request *validators_models.ValidatedAuthorizeRequest) string {
	t.Helper()

	code := storage_models.NewAuthorizationCode()
	code.ClientId = request.ClientId
	code.CreationTime = f.clock.now
	code.Lifetime = f.client.AuthorizationCodeLifetime
	code.RedirectUri = request.RedirectUri
	code.RequestedScopes = append([]string(nil), request.RequestedScopes...)
	code.RequestedResourceGaps = append([]string(nil), request.RequestedResourceIndiators...)
	code.Subject = request.Subject
	handle := "resource-code"
	if err := f.authorizationCodes.StoreAuthorizationCode(context.Background(), handle, code); err != nil {
		t.Fatalf("store authorization code: %v", err)
	}
	return handle
}

func (f *resourceIndicatorE2EFixture) validateAuthorizationCodeToken(t *testing.T, codeHandle string, resource string) *validators_models.TokenRequestValidationResult {
	t.Helper()

	values := url.Values{
		gois.TokenRequestGrantType:   {gois.GrantTypeAuthorizationCode},
		gois.TokenRequestCode:        {codeHandle},
		gois.TokenRequestRedirectUri: {f.client.RedirectUris[0]},
	}
	if resource != "" {
		values.Set(gois.TokenRequestResource, resource)
	}
	result, err := f.tokenValidator.ValidateRequest(context.Background(), values, &validators_models.ClientSecretValidationResult{Client: f.client})
	if err != nil {
		return nil
	}
	return result
}

func (f *resourceIndicatorE2EFixture) validateRefreshToken(t *testing.T, refreshHandle string, resource string) *validators_models.TokenRequestValidationResult {
	t.Helper()

	values := url.Values{
		gois.TokenRequestGrantType:    {gois.GrantTypeRefreshToken},
		gois.TokenRequestRefreshToken: {refreshHandle},
	}
	if resource != "" {
		values.Set(gois.TokenRequestResource, resource)
	}
	result, err := f.tokenValidator.ValidateRequest(context.Background(), values, &validators_models.ClientSecretValidationResult{Client: f.client})
	if err != nil {
		return nil
	}
	return result
}

func assertLastAccessTokenAudience(t *testing.T, recorder *resourceIndicatorTokenRecorder, want []string) {
	t.Helper()

	for i := len(recorder.tokens) - 1; i >= 0; i-- {
		token := recorder.tokens[i]
		if token.Type == gois.TokenTypesAccessToken {
			assertSameStrings(t, token.Audiences, want)
			return
		}
	}
	t.Fatal("no access token was recorded")
}

func assertSameStrings(t *testing.T, got []string, want []string) {
	t.Helper()

	got = sortedResourceIndicatorStrings(got)
	want = sortedResourceIndicatorStrings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("values = %v, want %v", got, want)
	}
}

func sortedResourceIndicatorStrings(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}
