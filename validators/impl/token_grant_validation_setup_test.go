// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"github.com/gonewx/wicket"
	claimspkg "github.com/gonewx/wicket/claims"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/services"
	services_impl "github.com/gonewx/wicket/services/impl"
	storage_impl "github.com/gonewx/wicket/storage/impl"
	"github.com/gonewx/wicket/storage/memory"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/utils"
	"github.com/gonewx/wicket/validators"
	validators_mock "github.com/gonewx/wicket/validators/mock"
	validators_models "github.com/gonewx/wicket/validators/models"
	"io"
	"log/slog"
	"net/url"
	"testing"
	"time"
)

// grantValidationTestNow is the fixed reference instant injected into token
// grant validation tests so lifetime arithmetic never depends on the real
// wall clock.
var grantValidationTestNow = time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)

// grantTestCodeVerifier satisfies the minimum proof key verifier length so
// verifier/challenge comparisons exercise the digest logic, not the length
// gate.
const grantTestCodeVerifier = "correct-horse-battery-staple-0123456789-abcdefghij"

// discardTestLogger returns a logger that swallows all output so table
// tests exercising failure paths stay quiet.
func discardTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// tokenGrantFixture bundles a TokenRequestValidator with the stores a test
// needs to seed grants into before exchanging them.
type tokenGrantFixture struct {
	validator          *TokenRequestValidator
	authorizationCodes *storage_impl.AuthorizationCodeStore
	refreshTokens      *storage_impl.RefreshTokenStore
	options            *config_options.WicketOptions
	now                time.Time
}

type tokenGrantConfig struct {
	resourceValidator validators.ResourceValidator
	resourceOwner     validators.ResourceOwnerPasswordValidator
	profile           services.ProfileService
	deviceCodes       validators.DeviceCodeValidator
	extensionGrants   []validators.ExtensionGrantValidator
}

type tokenGrantOption func(*tokenGrantConfig)

// withGrantResourceValidator swaps the real resource validator for a caller
// supplied one, typically to force scope or resource failures.
func withGrantResourceValidator(v validators.ResourceValidator) tokenGrantOption {
	return func(c *tokenGrantConfig) { c.resourceValidator = v }
}

// withGrantResourceOwnerValidator swaps the password credential validator.
func withGrantResourceOwnerValidator(v validators.ResourceOwnerPasswordValidator) tokenGrantOption {
	return func(c *tokenGrantConfig) { c.resourceOwner = v }
}

// withGrantProfile swaps the profile service, typically to mark users as
// disabled.
func withGrantProfile(p services.ProfileService) tokenGrantOption {
	return func(c *tokenGrantConfig) { c.profile = p }
}

// withGrantDeviceCodeValidator swaps the device code validator.
func withGrantDeviceCodeValidator(v validators.DeviceCodeValidator) tokenGrantOption {
	return func(c *tokenGrantConfig) { c.deviceCodes = v }
}

// withGrantExtensionValidators registers extension grant validators.
func withGrantExtensionValidators(gs ...validators.ExtensionGrantValidator) tokenGrantOption {
	return func(c *tokenGrantConfig) { c.extensionGrants = gs }
}

// newTokenGrantFixture wires a TokenRequestValidator over the shared
// in-memory client and resource fixtures with a fixed clock, substituting
// permissive defaults for every seam a caller does not override.
func newTokenGrantFixture(t *testing.T, opts ...tokenGrantOption) *tokenGrantFixture {
	t.Helper()

	cfg := &tokenGrantConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	logger := discardTestLogger()

	options := config_options.NewWicketOptions()

	scopes := &validators_mock.TestScopes{}
	resourceStore, err := memory.NewMemoryResourcesStore(scopes.GetIdentity(), scopes.GetApis(), scopes.GetScopes())
	if err != nil {
		t.Fatalf("resource store: %v", err)
	}

	if cfg.resourceValidator == nil {
		cfg.resourceValidator = NewResourceValidator(resourceStore, NewScopeParser(), logger)
	}
	if cfg.resourceOwner == nil {
		cfg.resourceOwner = validators_mock.NewTestResourceOwnerPasswordValidator(nil, "")
	}
	if cfg.profile == nil {
		cfg.profile = validators_mock.NewTestProfileService(true)
	}
	if cfg.deviceCodes == nil {
		cfg.deviceCodes = validators_mock.NewTestDeviceCodeValidator(false)
	}

	authorizationCodes := storage_impl.NewAuthorizationCodeStore()
	refreshTokens := storage_impl.NewRefreshTokenStore()

	validator := NewTokenRequestValidator(
		options,
		services_impl.NewIssuerNameService(options),
		authorizationCodes,
		NewExtensionGrantValidator(cfg.extensionGrants, logger),
		NewCustomTokenRequestValidator(),
		cfg.resourceValidator,
		resourceStore,
		services_impl.NewRefreshTokenService(refreshTokens, services_impl.NewHandleGenerationService()),
		cfg.resourceOwner,
		cfg.profile,
		cfg.deviceCodes,
		nil,
		fixedTestClock{now: grantValidationTestNow},
		logger,
	)

	return &tokenGrantFixture{
		validator:          validator,
		authorizationCodes: authorizationCodes,
		refreshTokens:      refreshTokens,
		options:            options,
		now:                grantValidationTestNow,
	}
}

// grantTestClient resolves a client from the shared client fixtures by id.
func grantTestClient(t *testing.T, clientId string) *storage_models.Client {
	t.Helper()

	for _, client := range (validators_mock.TestClients{}).Get() {
		if client.ClientId == clientId {
			return client
		}
	}

	t.Fatalf("unknown test client %q", clientId)
	return nil
}

// grantTestSecretResult wraps a fixture client into the client validation
// result the token request validator expects from the secret validation
// stage.
func grantTestSecretResult(t *testing.T, clientId string) *validators_models.ClientSecretValidationResult {
	t.Helper()

	result := validators_models.NewClientSecretValidationResult()
	result.Client = grantTestClient(t, clientId)
	return result
}

// grantTestSubject builds a principal carrying the given subject id, matching
// what an interactive authentication would have produced.
func grantTestSubject(subjectId string) *claimspkg.ClaimsPrincipal {
	identity := claimspkg.NewClaimsIdentity(
		claimspkg.WithAuthenticationType("test"),
		claimspkg.WithClaims([]*claimspkg.Claim{
			claimspkg.NewClaim(
				claimspkg.WithClaimType(wicket.JwtClaimTypesSubject),
				claimspkg.WithClaimValue(subjectId),
			),
		}),
	)
	return claimspkg.NewClaimsPrincipal(claimspkg.WithClaimsPrincipalIdentity(identity))
}

// grantTestPlainChallenge derives the stored challenge digest for the plain
// proof key method.
func grantTestPlainChallenge(verifier string) string {
	return utils.Sha256(verifier)
}

// grantTestS256Challenge derives the stored challenge digest for the S256
// proof key method: the verifier is first transformed to
// BASE64URL(SHA256(verifier)) and the digest of that transformation is
// stored.
func grantTestS256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return utils.Sha256(base64.RawURLEncoding.EncodeToString(sum[:]))
}

// grantTestFailingResources builds a resource validator stub whose result
// reports the given invalid scopes and invalid resource gaps.
func grantTestFailingResources(invalidScopes, invalidResourceGaps []string) validators.ResourceValidator {
	result := validators_models.NewResourceValidationResult()
	result.InvalidScopes = invalidScopes
	result.InvalidResourceGaps = invalidResourceGaps
	return &fixedResultResourceValidator{result: result}
}

// fixedResultResourceValidator always answers resource validation with a
// pre-built result.
type fixedResultResourceValidator struct {
	result *validators_models.ResourceValidationResult
}

func (v *fixedResultResourceValidator) ParseRequestedScopes(scopeValues []string) []*validators_models.ParsedScopeValue {
	parsed := make([]*validators_models.ParsedScopeValue, 0, len(scopeValues))
	for _, value := range scopeValues {
		parsed = append(parsed, &validators_models.ParsedScopeValue{RawValue: value, ParsedName: value})
	}
	return parsed
}

func (v *fixedResultResourceValidator) ValidateRequestedResources(ctx context.Context, request *validators_models.ResourceValidationRequest) (*validators_models.ResourceValidationResult, error) {
	return v.result, nil
}

// storeGrantTestAuthorizationCode persists an authorization code and returns
// its handle.
func storeGrantTestAuthorizationCode(t *testing.T, f *tokenGrantFixture, code *storage_models.AuthorizationCode) string {
	t.Helper()

	handle := "grant-code"
	if err := f.authorizationCodes.StoreAuthorizationCode(context.Background(), handle, code); err != nil {
		t.Fatalf("store authorization code: %v", err)
	}
	return handle
}

// newGrantTestAuthorizationCode builds an authorization code that is valid
// for exchange at the fixture's fixed clock instant.
func newGrantTestAuthorizationCode(clientId string, now time.Time) *storage_models.AuthorizationCode {
	code := storage_models.NewAuthorizationCode()
	code.ClientId = clientId
	code.Subject = grantTestSubject("818727")
	code.CreationTime = now
	code.Lifetime = 300
	code.RedirectUri = "https://server/cb"
	code.RequestedScopes = []string{"openid"}
	code.IsOpenId = true
	return code
}

// storeGrantTestRefreshToken persists a refresh token and returns its handle.
func storeGrantTestRefreshToken(t *testing.T, f *tokenGrantFixture, token *storage_models.RefreshToken) string {
	t.Helper()

	handle := "grant-refresh"
	if err := f.refreshTokens.StoreRefreshToken(context.Background(), handle, token); err != nil {
		t.Fatalf("store refresh token: %v", err)
	}
	return handle
}

// newGrantTestRefreshToken builds a refresh token that is valid for exchange
// at the fixture's fixed clock instant.
func newGrantTestRefreshToken(clientId string, now time.Time) *storage_models.RefreshToken {
	token := storage_models.NewRefreshToken()
	token.ClientId = clientId
	token.Subject = grantTestSubject("818727")
	token.CreationTime = now
	token.Lifetime = 600
	token.AuthorizedScopes = []string{"resource", wicket.StandardScopesOfflineAccess}
	token.SetAccessToken(&storage_models.Token{ClientId: clientId}, "")
	return token
}

// failingAuthorizationCodeStore returns an infrastructure error distinct from
// the not-found sentinel, so the merge-point split can be pinned: an infra
// failure surfaces through the validator's error channel instead of being
// disguised as invalid_grant.
type failingAuthorizationCodeStore struct{}

func (failingAuthorizationCodeStore) StoreAuthorizationCode(context.Context, string, *storage_models.AuthorizationCode) error {
	return errors.New("store unavailable")
}
func (failingAuthorizationCodeStore) GetAuthorizationCode(context.Context, string) (*storage_models.AuthorizationCode, error) {
	return nil, errors.New("store unavailable")
}
func (failingAuthorizationCodeStore) TakeAuthorizationCode(context.Context, string) (*storage_models.AuthorizationCode, error) {
	return nil, errors.New("store unavailable")
}
func (failingAuthorizationCodeStore) RemoveAuthorizationCode(context.Context, string) error {
	return errors.New("store unavailable")
}
func (failingAuthorizationCodeStore) RemoveAuthorizationCodesByClient(context.Context, string) (int, error) {
	return 0, errors.New("store unavailable")
}
func (failingAuthorizationCodeStore) RemoveAuthorizationCodesBySession(context.Context, string) (int, error) {
	return 0, errors.New("store unavailable")
}
func (failingAuthorizationCodeStore) RemoveExpired(context.Context, time.Time) (int, error) {
	return 0, errors.New("store unavailable")
}

// TestAuthorizationCodeInfrastructureFailureSurfacesAsError pins AC#3: only a
// missing code maps to invalid_grant; a store failure must reach the caller as
// an error, never as a protocol rejection.
func TestAuthorizationCodeInfrastructureFailureSurfacesAsError(t *testing.T) {
	t.Parallel()

	client := storage_models.NewClient()
	if err := client.SetAllowedGrantTypes(wicket.GrantTypesCode); err != nil {
		t.Fatalf("set grants: %v", err)
	}
	options := config_options.NewWicketOptions()
	logger := discardTestLogger()
	resourceStore, err := memory.NewMemoryResourcesStore(nil, nil, nil)
	if err != nil {
		t.Fatalf("resource store: %v", err)
	}
	validator := NewTokenRequestValidator(
		options,
		services_impl.NewIssuerNameService(options),
		failingAuthorizationCodeStore{},
		NewExtensionGrantValidator(nil, logger),
		NewCustomTokenRequestValidator(),
		NewResourceValidator(resourceStore, NewScopeParser(), logger),
		resourceStore,
		services_impl.NewRefreshTokenService(nil, services_impl.NewHandleGenerationService()),
		validators_mock.NewTestResourceOwnerPasswordValidator(nil, ""),
		validators_mock.NewTestProfileService(true),
		validators_mock.NewTestDeviceCodeValidator(false),
		nil,
		fixedTestClock{now: grantValidationTestNow},
		logger,
	)
	result, err := validator.ValidateRequest(context.Background(), url.Values{
		wicket.TokenRequestGrantType: {wicket.GrantTypeAuthorizationCode},
		wicket.TokenRequestCode:      {"some-code"},
	}, &validators_models.ClientSecretValidationResult{Client: client})
	if err == nil {
		t.Fatalf("expected infrastructure error, got result %+v", result)
	}
}
