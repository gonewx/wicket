// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package services

import (
	"context"
	"time"

	"github.com/gonewx/wicket/auth"
	"github.com/gonewx/wicket/claims"
	core_models "github.com/gonewx/wicket/models"
	"github.com/gonewx/wicket/models/contexts"
	"github.com/gonewx/wicket/models/messages"
	responses_models "github.com/gonewx/wicket/responses/models"
	"github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/tokens"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// SystemClock returns the current time.
// input: none -> behavior: read clock -> output: current time.
type SystemClock interface {
	Now() time.Time
}

// DistributedCache stores small opaque byte values by key.
// input: key/value/options -> behavior: set/get/remove cache item -> output: value or error.
type DistributedCache interface {
	Get(string) ([]byte, error)
	Set(string, []byte, *DistributedCacheEntryOptions) error
	Remove(string) error
}

type DistributedCacheEntryOptions struct {
	AbsoluteExpiration time.Time
}

// ServerUrls derives request-relative server URLs.
// input: current request -> behavior: derive origin/base/relative URL -> output: URL string.
type ServerUrls interface {
	Origin() string
	BasePath() string
	BaseUrl() string
	GetWicketRelativeUrl(string) string
}

// IssuerNameService returns the current issuer name.
// input: current request/options -> behavior: derive issuer -> output: issuer string.
type IssuerNameService interface {
	GetCurrent() string
}

// JwtRequestUriHttpClient retrieves JWT request objects.
// input: URL -> behavior: fetch body -> output: body or error.
type JwtRequestUriHttpClient interface {
	GetJwt(string, *models.Client) (string, error)
}

// CorsPolicyService decides whether an origin is allowed.
// input: origin -> behavior: evaluate client origins -> output: allowed flag.
type CorsPolicyService interface {
	IsOriginAllowed(string) bool
}

// UserSession tracks the current user session.
// input: principal/properties/client id -> behavior: create/read session state -> output: session data or error.
type UserSession interface {
	EnsureSessionIdCookie(ctx context.Context) error
	RemoveSessionIdCookie() error
	CreateSessionId(ctx context.Context, principal *claims.ClaimsPrincipal, properties *auth.Properties) (string, error)
	GetSessionId() string
	GetClientList() ([]string, error)
	GetUser() *claims.ClaimsPrincipal
	AddClientId(ctx context.Context, clientId string) error
	Item(string) (any, bool)
	SetItem(string, any)
}

// ProfileService supplies profile claims and active-state checks.
// input: profile/is-active context -> behavior: mutate context -> output: context fields or error.
type ProfileService interface {
	GetProfileData(*contexts.ProfileDataRequestContext)
	IsActive(*contexts.IsActiveContext)
}

// ClaimsService creates token claims from current request context.
// input: subject/resources/request -> behavior: select claims -> output: claims or error.
type ClaimsService interface {
	GetIdentityTokenClaims(*claims.ClaimsPrincipal, *validators_models.ResourceValidationResult, bool, *validators_models.ValidatedRequest) ([]*claims.Claim, error)
	GetAccessTokenClaims(*claims.ClaimsPrincipal, *validators_models.ResourceValidationResult, *validators_models.ValidatedRequest) ([]*claims.Claim, error)
}

// KeyMaterialService exposes signing and validation key material.
// input: allowed algorithms -> behavior: choose configured key material -> output: credentials/keys or error.
type KeyMaterialService interface {
	GetSigningCredentials(ctx context.Context, allowed []string) (*tokens.SigningCredentials, error)
	GetAllSigningCredentials(ctx context.Context) ([]*tokens.SigningCredentials, error)
	GetValidationKeys(ctx context.Context) ([]*core_models.SecurityKeyInfo, error)
}

// TokenCreationService serializes a token.
// input: token model -> behavior: create serialized security token -> output: token string or error.
type TokenCreationService interface {
	CreateToken(ctx context.Context, token *models.Token) (string, error)
}

// TokenService creates protocol token models and serializes them.
// input: token creation request/model -> behavior: create or serialize token -> output: token model/string or error.
type TokenService interface {
	CreateAccessToken(ctx context.Context, request *responses_models.TokenCreationRequest) (*models.Token, error)
	CreateIdentityToken(ctx context.Context, request *responses_models.TokenCreationRequest) (*models.Token, error)
	CreateSecurityToken(ctx context.Context, token *models.Token) (string, error)
}

// RefreshTokenService manages refresh token handles.
// input: refresh token request/handle -> behavior: create, validate, or update -> output: handle/result or error.
type RefreshTokenService interface {
	CreateRefreshToken(ctx context.Context, request *responses_models.RefreshTokenCreationRequest) (string, error)
	UpdateRefreshToken(ctx context.Context, request *responses_models.RefreshTokenUpdateRequest) (string, error)
	ValidateRefreshToken(ctx context.Context, handle string, client *models.Client) *validators_models.TokenValidationResult
}

// PersistedGrantService removes persisted grants for subjects and clients.
// input: subject/client/session -> behavior: remove grants -> output: error.
type PersistedGrantService interface {
	RemoveAllGrantsAsync(ctx context.Context, subjectId, clientId, sessionId string) error
}

// HandleGenerationService creates opaque handles.
// input: none -> behavior: generate random handle -> output: handle string or error.
type HandleGenerationService interface {
	Generate() (string, error)
}

// UserCodeGenerator creates device-flow user codes.
// input: none -> behavior: generate code and expose policy -> output: code/type/retry limit.
type UserCodeGenerator interface {
	Generate() string
	GetUserCodeType() string
	GetRetryLimit() int
}

// UserCodeService chooses a user-code generator by type.
// input: code type -> behavior: select generator -> output: generator.
type UserCodeService interface {
	GetGenerator(string) UserCodeGenerator
}

// DeviceFlowCodeService stores and retrieves device-flow codes.
// input: user/device code -> behavior: store/find/update device authorization -> output: data or error.
type DeviceFlowCodeService interface {
	StoreDeviceAuthorization(ctx context.Context, userCode string, data *models.DeviceCode) (string, error)
	FindByUserCode(ctx context.Context, userCode string) (*models.DeviceCode, error)
	FindByDeviceCode(ctx context.Context, deviceCode string) (*models.DeviceCode, error)
	UpdateByUserCode(ctx context.Context, userCode string, data *models.DeviceCode) error
	RemoveByDeviceCode(ctx context.Context, deviceCode string) error
}

// ConsentService evaluates and stores user consent for an authorization request.
// input: subject/client/scopes or authorization request/consent -> behavior: decide
// whether consent is required, persist a remembered decision, or grant/deny consent
// -> output: decision flag or error.
type ConsentService interface {
	RequiresConsent(*claims.ClaimsPrincipal, *models.Client, []*validators_models.ParsedScopeValue) (bool, error)
	UpdateConsent(*claims.ClaimsPrincipal, *models.Client, []*validators_models.ParsedScopeValue) error
	GrantConsent(*messages.AuthorizationRequest, *messages.ConsentResponse, string) error
	DenyAuthorization(*messages.AuthorizationRequest, string) error
}

// InteractionService reads and updates user-interaction state.
// input: return URL/request/consent -> behavior: retrieve context or persist decision -> output: context or error.
type InteractionService interface {
	GetAuthorizationContext(ctx context.Context, returnUrl string) (*messages.AuthorizationRequest, error)
	GetLogoutContext(ctx context.Context, logoutId string) (*messages.LogoutRequest, error)
	GetErrorContext(ctx context.Context, errorId string) (*messages.ErrorMessage, error)
	GrantConsent(ctx context.Context, request *messages.AuthorizationRequest, consent *messages.ConsentResponse, subject string) error
	DenyAuthorization(ctx context.Context, request *messages.AuthorizationRequest, subject string) error
}

// BackchannelLogoutService sends back-channel logout notifications.
// input: logout context -> behavior: dispatch notifications -> output: error.
type BackchannelLogoutService interface {
	SendLogoutNotificationsAsync(*contexts.LogoutNotificationContext) error
}

// DeviceFlowThrottlingService enforces device-flow polling interval.
// input: device code/details -> behavior: check throttling state -> output: slow-down flag or error.
type DeviceFlowThrottlingService interface {
	ShouldSlowDown(ctx context.Context, deviceCode string, details *models.DeviceCode) (bool, error)
}

// BackchannelAuthenticationNotificationService sends CIBA ping/push notifications.
// input: request state -> behavior: notify client endpoint when configured -> output: error.
type BackchannelAuthenticationNotificationService interface {
	Notify(*models.BackchannelAuthenticationRequest) error
}

// BackchannelAuthenticationThrottlingService enforces per-request CIBA poll interval.
// input: request id/details -> behavior: update poll timing when needed -> output: slow-down flag or error.
type BackchannelAuthenticationThrottlingService interface {
	ShouldSlowDown(string, *models.BackchannelAuthenticationRequest) (bool, error)
}

type SessionValidationType string

const SessionValidationTypeAccessToken SessionValidationType = "access_token"

type SessionValidationRequest struct {
	Type      SessionValidationType
	Token     string
	Client    *models.Client
	ClientId  string
	SubjectId string
	SessionId string
}

// SessionCoordinationService validates whether a referenced session is still
// valid during token use. input: session validation request -> behavior:
// pass-through when server-side sessions are disabled, real store-backed
// validation when enabled -> output: validity flag or error.
type SessionCoordinationService interface {
	ValidateSession(ctx context.Context, request *SessionValidationRequest) (bool, error)
}
