// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/accessor"
	"github.com/gonewx/wicket/auth"
	"github.com/gonewx/wicket/claims"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/extensions"
	"github.com/gonewx/wicket/models/contexts"
	"github.com/gonewx/wicket/models/messages"
	responses_models "github.com/gonewx/wicket/responses/models"
	"github.com/gonewx/wicket/services"
	sessionpkg "github.com/gonewx/wicket/session"
	"github.com/gonewx/wicket/storage"
	storage_models "github.com/gonewx/wicket/storage/models"
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
	return "", fmt.Errorf("JWT request URI retrieval pending Epic 2/3 implementation")
}

func (c *JwtRequestUriHttpClient) GetJwt(uri string, client *storage_models.Client) (string, error) {
	return c.Get(uri)
}

type UserSession struct {
	accessor       accessor.HttpContextAccessor
	items          map[string]any
	user           *claims.ClaimsPrincipal
	session        string
	clients        []string
	store          sessionpkg.Store
	clock          services.SystemClock
	logger         *slog.Logger
	enabled        bool
	lifetime       time.Duration
	cookieName     string
	cookieSecure   bool
	cookieSameSite http.SameSite
}

func NewUserSession(
	accessor accessor.HttpContextAccessor,
	handlerProvider auth.HandlerProvider,
	options *config_options.WicketOptions,
	clock services.SystemClock,
	urls services.ServerUrls,
	logger *slog.Logger,
	schemes auth.SchemeProvider,
	store sessionpkg.Store,
) *UserSession {
	enabled := false
	lifetime := 14 * 24 * time.Hour
	cookieName := "wicket.session"
	cookieSecure := true
	cookieSameSite := http.SameSiteNoneMode
	if options != nil && options.ServerSideSessions != nil {
		enabled = options.ServerSideSessions.Enabled
		if options.ServerSideSessions.SessionLifetime > 0 {
			lifetime = options.ServerSideSessions.SessionLifetime
		}
		if options.ServerSideSessions.CookieName != "" {
			cookieName = options.ServerSideSessions.CookieName
		}
		cookieSecure = options.ServerSideSessions.CookieSecure
		if options.ServerSideSessions.CookieSameSite != 0 {
			cookieSameSite = options.ServerSideSessions.CookieSameSite
		}
	}
	return &UserSession{
		accessor:       accessor,
		items:          map[string]any{},
		store:          store,
		clock:          clock,
		logger:         logger,
		enabled:        enabled,
		lifetime:       lifetime,
		cookieName:     cookieName,
		cookieSecure:   cookieSecure,
		cookieSameSite: cookieSameSite,
	}
}

// responseWriter returns the current response writer when the accessor also
// exposes one; nil otherwise (e.g. outside a request scope).
func (s *UserSession) responseWriter() http.ResponseWriter {
	if s.accessor == nil {
		return nil
	}
	if rw, ok := s.accessor.(accessor.HttpResponseWriterAccessor); ok {
		return rw.ResponseWriter()
	}
	return nil
}

func (s *UserSession) writeSessionCookie(sessionID string) {
	w := s.responseWriter()
	if w == nil {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName,
		Value:    sessionID,
		MaxAge:   int(s.lifetime.Seconds()),
		HttpOnly: true,
		Secure:   s.cookieSecure,
		SameSite: s.cookieSameSite,
		Path:     "/",
	})
}

func (s *UserSession) clearSessionCookie() {
	w := s.responseWriter()
	if w == nil {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName,
		Value:    "",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   s.cookieSecure,
		SameSite: s.cookieSameSite,
		Path:     "/",
	})
}

func (s *UserSession) readSessionCookie() string {
	if s.accessor == nil {
		return ""
	}
	req := s.accessor.Request()
	if req == nil {
		return ""
	}
	cookie, err := req.Cookie(s.cookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// EnsureSessionIdCookie loads the session from the request cookie into internal
// state when server-side sessions are enabled. If the cookie references a
// session that is missing or expired, the cookie is cleared and internal state
// stays empty (graceful degradation, not an error).
func (s *UserSession) EnsureSessionIdCookie() error {
	if !s.enabled || s.store == nil {
		return nil
	}
	if s.session != "" {
		return nil
	}

	sessionID := s.readSessionCookie()
	if sessionID == "" {
		return nil
	}

	rec, err := s.store.GetSession(sessionID)
	if err != nil {
		return fmt.Errorf("load session: %w", err)
	}
	if rec == nil {
		s.clearSessionCookie()
		return nil
	}

	s.session = rec.SessionID
	s.clients = append([]string(nil), rec.ClientIDs...)
	return nil
}

func (s *UserSession) RemoveSessionIdCookie() error {
	if s.enabled {
		s.clearSessionCookie()
	}
	s.session = ""
	s.clients = nil
	return nil
}

func (s *UserSession) CreateSessionId(principal *claims.ClaimsPrincipal, properties *auth.Properties) (string, error) {
	s.user = principal
	s.session = newHandle()

	if s.enabled && s.store != nil {
		if s.clock == nil {
			s.session = ""
			s.user = nil
			return "", fmt.Errorf("create session: clock not configured")
		}
		now := s.clock.Now()
		rec := &sessionpkg.Record{
			SessionID: s.session,
			SubjectID: extensions.GetSubjectIdFromPrincipal(principal),
			Created:   now,
			Renewed:   now,
			Expires:   now.Add(s.lifetime),
		}
		if err := s.store.CreateSession(rec); err != nil {
			s.session = ""
			s.user = nil
			return "", fmt.Errorf("create session: %w", err)
		}
		s.writeSessionCookie(s.session)
	}

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

	if s.enabled && s.store != nil && s.session != "" {
		if err := s.store.AddClientID(s.session, clientId); err != nil && s.logger != nil {
			s.logger.Warn("failed to persist client id to session store",
				slog.String("sessionId", s.session),
				slog.String("clientId", clientId),
				slog.Any("err", err),
			)
		}
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
	audiences := []string(nil)
	if request.ValidatedResources != nil && request.ValidatedResources.Resources != nil {
		for _, resource := range request.ValidatedResources.Resources.ApiResources() {
			if resource != nil && resource.Name != "" && !utils.Contains(audiences, resource.Name) {
				audiences = append(audiences, resource.Name)
			}
		}
		sort.Strings(audiences)
	}
	return &storage_models.Token{CreationTime: s.clock.Now(), Type: gois.TokenTypesAccessToken, Claims: claims, Audiences: audiences}, nil
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
		request.RefreshToken.SetAccessToken(request.AccessToken, request.RequestedResourceGap)
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

func newHandle() string {
	id, err := utils.CreateUniqueId(32, utils.Hex)
	if err != nil {
		return ""
	}
	return id
}
