// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/accessor"
	"github.com/gonewx/wicket/auth"
	"github.com/gonewx/wicket/claims"
	config_options "github.com/gonewx/wicket/config/options"
	core_models "github.com/gonewx/wicket/models"
	"github.com/gonewx/wicket/models/contexts"
	"github.com/gonewx/wicket/models/messages"
	responses_models "github.com/gonewx/wicket/responses/models"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/storage"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/tokens"
	"github.com/gonewx/wicket/utils"
	validators_models "github.com/gonewx/wicket/validators/models"
)

type SystemClock struct{}

func NewSystemClock() SystemClock {
	return SystemClock{}
}

func (SystemClock) Now() time.Time {
	return time.Now().UTC()
}

type ServerUrls struct {
	request *http.Request
}

func NewServerUrls(request *http.Request) *ServerUrls {
	return &ServerUrls{request: request}
}

func NewServerUrlsFromAccessor(accessor accessor.HttpContextAccessor) *ServerUrls {
	if accessor == nil {
		return &ServerUrls{}
	}
	return &ServerUrls{request: accessor.Request()}
}

func (u *ServerUrls) Origin() string {
	if u == nil || u.request == nil {
		return ""
	}
	scheme := "http"
	if u.request.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + u.request.Host
}

func (u *ServerUrls) BasePath() string {
	if u == nil || u.request == nil {
		return ""
	}
	return ""
}

func (u *ServerUrls) BaseUrl() string {
	return utils.EnsureTrailingSlash(u.Origin() + u.BasePath())
}

func (u *ServerUrls) GetWicketRelativeUrl(value string) string {
	if strings.HasPrefix(value, "~/") {
		return utils.EnsureLeadingSlash(strings.TrimPrefix(value, "~/"))
	}
	if utils.IsUri(value) {
		return value
	}
	return utils.EnsureLeadingSlash(value)
}

type IssuerNameService struct {
	options *config_options.WicketOptions
	request *http.Request
}

func NewIssuerNameService(options *config_options.WicketOptions) *IssuerNameService {
	return &IssuerNameService{options: options}
}

func (s *IssuerNameService) Init(request *http.Request) {
	s.request = request
}

func (s *IssuerNameService) GetCurrent() string {
	if s != nil && s.options != nil && s.options.IssuerUri != "" {
		return strings.TrimRight(s.options.IssuerUri, "/")
	}
	return NewServerUrls(s.request).Origin()
}

type JwtRequestUriHttpClient struct {
	client  *http.Client
	options *config_options.WicketOptions
}

func NewJwtRequestUriHttpClient(client *http.Client, options *config_options.WicketOptions) *JwtRequestUriHttpClient {
	if client == nil {
		client = http.DefaultClient
	}
	return &JwtRequestUriHttpClient{client: client, options: options}
}

func (c *JwtRequestUriHttpClient) Get(uri string) (string, error) {
	return "", fmt.Errorf("JWT request URI retrieval pending Epic 2/3 clean-room rewrite")
}

func (c *JwtRequestUriHttpClient) GetJwt(uri string, client *storage_models.Client) (string, error) {
	return c.Get(uri)
}

type UserSession struct {
	accessor accessor.HttpContextAccessor
	items    map[string]any
	user     *claims.ClaimsPrincipal
	session  string
	clients  []string
}

func NewUserSession(
	accessor accessor.HttpContextAccessor,
	handlerProvider auth.HandlerProvider,
	options *config_options.WicketOptions,
	clock services.SystemClock,
	urls services.ServerUrls,
	logger *slog.Logger,
	schemes auth.SchemeProvider,
) *UserSession {
	return &UserSession{accessor: accessor, items: map[string]any{}}
}

func (s *UserSession) EnsureSessionIdCookie() error { return nil }
func (s *UserSession) RemoveSessionIdCookie() error { s.session = ""; return nil }
func (s *UserSession) CreateSessionId(principal *claims.ClaimsPrincipal, properties *auth.Properties) (string, error) {
	s.user = principal
	s.session = newHandle()
	return s.session, nil
}
func (s *UserSession) GetSessionId() string { return s.session }
func (s *UserSession) GetClientList() ([]string, error) {
	return append([]string(nil), s.clients...), nil
}
func (s *UserSession) GetUser() *claims.ClaimsPrincipal { return s.user }
func (s *UserSession) AddClientId(clientId string) error {
	if !utils.Contains(s.clients, clientId) {
		s.clients = append(s.clients, clientId)
	}
	return nil
}
func (s *UserSession) Item(key string) (any, bool) {
	v, ok := s.items[key]
	return v, ok
}
func (s *UserSession) SetItem(key string, item any) { s.items[key] = item }

type ProfileService struct {
	logger *slog.Logger
}

func NewProfileService(logger *slog.Logger) *ProfileService {
	return &ProfileService{logger: logger}
}

func (s *ProfileService) GetProfileData(ctx *contexts.ProfileDataRequestContext) {}
func (s *ProfileService) IsActive(ctx *contexts.IsActiveContext) {
	if ctx != nil {
		ctx.IsActive = true
	}
}

type ClaimsService struct{}

func NewClaimsService() ClaimsService { return ClaimsService{} }

func (ClaimsService) GetIdentityTokenClaims(subject *claims.ClaimsPrincipal, resources *validators_models.ResourceValidationResult, includeAllIdentityClaims bool, request *validators_models.ValidatedRequest) ([]*claims.Claim, error) {
	if subject == nil {
		return nil, nil
	}
	return subject.Claims(), nil
}

func (ClaimsService) GetAccessTokenClaims(subject *claims.ClaimsPrincipal, resources *validators_models.ResourceValidationResult, request *validators_models.ValidatedRequest) ([]*claims.Claim, error) {
	if subject == nil {
		return nil, nil
	}
	return subject.Claims(), nil
}

type KeyMaterialService struct {
	signingStores    []storage.SigningCredentialStore
	validationStores []storage.ValidationKeysStore
}

func NewKeyMaterialService(signingStores []storage.SigningCredentialStore, validationStores []storage.ValidationKeysStore) *KeyMaterialService {
	return &KeyMaterialService{signingStores: signingStores, validationStores: validationStores}
}

func (s *KeyMaterialService) GetSigningCredentials(allowed []string) (*tokens.SigningCredentials, error) {
	all, err := s.GetAllSigningCredentials()
	if err != nil || len(all) == 0 {
		return nil, err
	}
	return all[0], nil
}

func (s *KeyMaterialService) GetAllSigningCredentials() ([]*tokens.SigningCredentials, error) {
	out := make([]*tokens.SigningCredentials, 0)
	for _, store := range s.signingStores {
		credential, err := store.GetSigningCredentials()
		if err != nil {
			return nil, err
		}
		if credential != nil {
			out = append(out, credential)
		}
	}
	return out, nil
}

func (s *KeyMaterialService) GetValidationKeys() ([]*core_models.SecurityKeyInfo, error) {
	out := make([]*core_models.SecurityKeyInfo, 0)
	for _, store := range s.validationStores {
		keys, err := store.GetValidationKeys()
		if err != nil {
			return nil, err
		}
		out = append(out, keys...)
	}
	return out, nil
}

type TokenCreationService struct{}

func NewTokenCreationService() TokenCreationService { return TokenCreationService{} }
func (TokenCreationService) CreateToken(token *storage_models.Token) (string, error) {
	return newHandle(), nil
}

type TokenService struct {
	claims        services.ClaimsService
	reference     storage.ReferenceTokenStore
	tokenCreation services.TokenCreationService
	clock         services.SystemClock
	keys          services.KeyMaterialService
	options       *config_options.WicketOptions
	logger        *slog.Logger
	request       *http.Request
}

func NewTokenService(
	claims services.ClaimsService,
	reference storage.ReferenceTokenStore,
	tokenCreation services.TokenCreationService,
	clock services.SystemClock,
	keys services.KeyMaterialService,
	options *config_options.WicketOptions,
	logger *slog.Logger,
	request *http.Request,
) *TokenService {
	return &TokenService{claims: claims, reference: reference, tokenCreation: tokenCreation, clock: clock, keys: keys, options: options, logger: logger, request: request}
}

func (s *TokenService) CreateAccessToken(request *responses_models.TokenCreationRequest) (*storage_models.Token, error) {
	claims := []*claims.Claim(nil)
	if request.Subject != nil {
		claims = request.Subject.Claims()
	}
	return &storage_models.Token{CreationTime: s.clock.Now(), Type: gois.TokenTypesAccessToken, Claims: claims}, nil
}

func (s *TokenService) CreateIdentityToken(request *responses_models.TokenCreationRequest) (*storage_models.Token, error) {
	claims := []*claims.Claim(nil)
	if request.Subject != nil {
		claims = request.Subject.Claims()
	}
	return &storage_models.Token{CreationTime: s.clock.Now(), Type: gois.TokenTypesIdentityToken, Claims: claims}, nil
}

func (s *TokenService) CreateSecurityToken(token *storage_models.Token) (string, error) {
	return s.tokenCreation.CreateToken(token)
}

type RefreshTokenService struct {
	store storage.RefreshTokenStore
}

func NewRefreshTokenService(store storage.RefreshTokenStore) *RefreshTokenService {
	return &RefreshTokenService{store: store}
}

func (s *RefreshTokenService) CreateRefreshToken(request *responses_models.RefreshTokenCreationRequest) (string, error) {
	token := storage_models.NewRefreshToken()
	token.Subject = request.Subject
	token.ClientId = request.Client.ClientId
	token.Description = request.Description
	token.AuthorizedScopes = request.AuthorizedScopes
	token.AuthorizedResourceGaps = request.AuthorizedResourceGaps
	token.SetAccessToken(request.AccessToken, request.RequestedResourceGap)
	return s.store.StoreRefreshToken(token)
}

func (s *RefreshTokenService) UpdateRefreshToken(request *responses_models.RefreshTokenUpdateRequest) (string, error) {
	if request.RefreshToken != nil && request.AccessToken != nil {
		request.RefreshToken.SetAccessToken(request.AccessToken, "")
	}
	return request.Handle, s.store.UpdateRefreshToken(request.Handle, request.RefreshToken)
}

func (s *RefreshTokenService) ValidateRefreshToken(handle string, client *storage_models.Client) *validators_models.TokenValidationResult {
	token, err := s.store.GetRefreshToken(handle)
	result := validators_models.NewTokenValidationResult()
	if err != nil || token == nil {
		result.Error = fmt.Errorf("refresh token not found")
		return result
	}
	result.RefreshToken = token
	result.Client = client
	result.Subject = token.Subject
	return result
}

type PersistedGrantService struct {
	store storage.PersistedGrantStore
}

func NewPersistedGrantService(store storage.PersistedGrantStore) *PersistedGrantService {
	return &PersistedGrantService{store: store}
}

func (s *PersistedGrantService) RemoveAllGrantsAsync(subjectId, clientId, sessionId string) error {
	return s.store.RemoveAll(&storage.PersistedGrantFilter{SubjectId: subjectId, ClientId: clientId, SessionId: sessionId})
}

type HandleGenerationService struct{}

func NewHandleGenerationService() HandleGenerationService { return HandleGenerationService{} }
func (HandleGenerationService) Generate() string          { return newHandle() }

type UserCodeService struct {
	generators []services.UserCodeGenerator
}

func NewUserCodeService(generators []services.UserCodeGenerator) *UserCodeService {
	return &UserCodeService{generators: generators}
}

func (s *UserCodeService) GetGenerator(codeType string) services.UserCodeGenerator {
	if len(s.generators) > 0 {
		return s.generators[0]
	}
	return NewNumericUserCodeGenerator()
}

type DeviceFlowCodeService struct {
	store   storage.DeviceFlowStore
	handles services.HandleGenerationService
}

func NewDeviceFlowCodeService(store storage.DeviceFlowStore, handles services.HandleGenerationService) *DeviceFlowCodeService {
	return &DeviceFlowCodeService{store: store, handles: handles}
}

func (s *DeviceFlowCodeService) StoreDeviceAuthorization(userCode string, data *storage_models.DeviceCode) (string, error) {
	deviceCode := s.handles.Generate()
	return deviceCode, s.store.StoreDeviceAuthorization(deviceCode, userCode, data)
}
func (s *DeviceFlowCodeService) FindByUserCode(userCode string) (*storage_models.DeviceCode, error) {
	return s.store.FindByUserCode(userCode)
}
func (s *DeviceFlowCodeService) FindByDeviceCode(deviceCode string) (*storage_models.DeviceCode, error) {
	return s.store.FindByDeviceCode(deviceCode)
}
func (s *DeviceFlowCodeService) UpdateByUserCode(userCode string, data *storage_models.DeviceCode) error {
	return s.store.UpdateByUserCode(userCode, data)
}
func (s *DeviceFlowCodeService) RemoveByDeviceCode(deviceCode string) error {
	return s.store.RemoveByDeviceCode(deviceCode)
}

type ConsentService struct{}

func NewConsentService() ConsentService { return ConsentService{} }
func (ConsentService) GrantConsent(*messages.AuthorizationRequest, *messages.ConsentResponse, string) error {
	return nil
}
func (ConsentService) DenyAuthorization(*messages.AuthorizationRequest, string) error { return nil }

type InteractionService struct {
	consent services.ConsentService
	logout  storage.MessageStore[messages.LogoutMessage]
	errors  storage.MessageStore[messages.ErrorMessage]
}

func NewInteractionService(clock services.SystemClock, logout storage.MessageStore[messages.LogoutMessage], errors storage.MessageStore[messages.ErrorMessage], consentStore storage.ConsentMessageStore, grants services.PersistedGrantService, user services.UserSession, logger *slog.Logger, parser *ReturnUrlParser, urls services.ServerUrls, notifications storage.MessageStore[contexts.LogoutNotificationContext]) *InteractionService {
	return &InteractionService{consent: NewConsentService(), logout: logout, errors: errors}
}

func (s *InteractionService) GetAuthorizationContext(returnUrl string) (*messages.AuthorizationRequest, error) {
	return &messages.AuthorizationRequest{}, nil
}
func (s *InteractionService) GetLogoutContext(logoutId string) (*messages.LogoutRequest, error) {
	if s.logout == nil || logoutId == "" {
		return messages.NewLogoutRequest("", nil), nil
	}
	message, err := s.logout.Read(logoutId)
	if err != nil || message == nil {
		return messages.NewLogoutRequest("", nil), err
	}
	return messages.NewLogoutRequest("", message.Data), nil
}
func (s *InteractionService) GetErrorContext(errorId string) (*messages.ErrorMessage, error) {
	if s.errors == nil || errorId == "" {
		return messages.NewErrorMessage(), nil
	}
	message, err := s.errors.Read(errorId)
	if err != nil || message == nil || message.Data == nil {
		return messages.NewErrorMessage(), err
	}
	return message.Data, nil
}
func (s *InteractionService) GrantConsent(request *messages.AuthorizationRequest, response *messages.ConsentResponse, subject string) error {
	return s.consent.GrantConsent(request, response, subject)
}
func (s *InteractionService) DenyAuthorization(request *messages.AuthorizationRequest, subject string) error {
	return s.consent.DenyAuthorization(request, subject)
}

type BackchannelLogoutService struct {
	notifications services.LogoutNotificationService
	client        services.BackChannelLogoutHttpClient
}

func NewBackchannelLogoutService(notifications services.LogoutNotificationService, client services.BackChannelLogoutHttpClient, logger *slog.Logger) *BackchannelLogoutService {
	return &BackchannelLogoutService{notifications: notifications, client: client}
}

func (s *BackchannelLogoutService) SendLogoutNotificationsAsync(ctx *contexts.LogoutNotificationContext) error {
	return nil
}

type SessionCoordinationService struct{}

func NewSessionCoordinationService() SessionCoordinationService { return SessionCoordinationService{} }
func (SessionCoordinationService) ValidateSession(*services.SessionValidationRequest) (bool, error) {
	return false, fmt.Errorf("server-side session validation pending Epic 2/3 clean-room rewrite")
}

func newHandle() string {
	id, err := utils.CreateUniqueId(32, utils.Hex)
	if err != nil {
		return ""
	}
	return id
}
