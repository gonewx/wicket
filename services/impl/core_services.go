// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	"github.com/gonewx/wicket/dpop"
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
		return u.BaseUrl() + strings.TrimPrefix(value, "~/")
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

// GetJwt fetches a request object from the given request_uri. The response
// body is bounded by the configured JWT input length so a misbehaving server
// cannot amplify memory, and every failure (transport, non-2xx, oversized
// body) surfaces as an error for the caller to classify as invalid_request_uri.
func (c *JwtRequestUriHttpClient) GetJwt(uri string, client *storage_models.Client) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), jwtRequestUriFetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return "", fmt.Errorf("build request object fetch: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch request object: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("request object fetch returned status %d", resp.StatusCode)
	}

	limit := c.options.InputLengthRestrictions.Jwt
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
	if err != nil {
		return "", fmt.Errorf("read request object body: %w", err)
	}
	if len(body) > limit {
		return "", fmt.Errorf("request object body exceeds the %d byte limit", limit)
	}

	return string(body), nil
}

const jwtRequestUriFetchTimeout = 10 * time.Second

type UserSession struct {
	accessor        accessor.HttpContextAccessor
	handlerProvider auth.HandlerProvider
	schemes         auth.SchemeProvider
	items           map[string]any
	user            *claims.ClaimsPrincipal
	session         string
	clients         []string
	store           sessionpkg.Store
	clock           services.SystemClock
	logger          *slog.Logger
	enabled         bool
	lifetime        time.Duration
	cookieName      string
	cookieSecure    bool
	cookieSameSite  http.SameSite
	// restoreDone records that this request-scoped instance already tried to
	// restore its session from the session cookie, or no longer may (after a
	// session was created or removed in this request).
	restoreDone bool

	// revoker, when set, removes the grants of the session named by the
	// session cookie once another subject signs in on it, see
	// SetSessionGrantRevoker. revokedSession is the session this instance
	// already revoked, so one request revokes it at most once.
	revoker        *SessionGrantRevoker
	revokedSession string
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
		accessor:        accessor,
		handlerProvider: handlerProvider,
		schemes:         schemes,
		items:           map[string]any{},
		store:           store,
		clock:           clock,
		logger:          logger,
		enabled:         enabled,
		lifetime:        lifetime,
		cookieName:      cookieName,
		cookieSecure:    cookieSecure,
		cookieSameSite:  cookieSameSite,
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
func (s *UserSession) EnsureSessionIdCookie(ctx context.Context) error {
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

	rec, err := s.store.GetSession(ctx, sessionID)
	if err != nil {
		if errors.Is(err, sessionpkg.ErrSessionNotFound) {
			s.clearSessionCookie()
			return nil
		}
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
	s.restoreDone = true
	return nil
}

// restore lazily recovers the session referenced by the session cookie of the
// current request, at most once per instance. The recovered session is adopted
// only when the request carries an authenticated user whose subject is the
// session's subject; otherwise the request is treated as having no session and
// the cookie is cleared. A store failure is logged and the request is treated
// as having no session too, but the cookie is kept for a later request; the
// request does not fail.
func (s *UserSession) restore() {
	if s.session != "" || s.restoreDone {
		return
	}
	s.restoreDone = true
	if !s.enabled || s.store == nil || s.accessor == nil {
		return
	}
	request := s.accessor.Request()
	if request == nil {
		return
	}
	sessionID := s.readSessionCookie()
	if sessionID == "" {
		return
	}

	rec, err := s.store.GetSession(request.Context(), sessionID)
	if err != nil {
		if errors.Is(err, sessionpkg.ErrSessionNotFound) {
			s.clearSessionCookie()
			return
		}
		if s.logger != nil {
			s.logger.Warn("restore session: cannot load session", slog.String("error", err.Error()))
		}
		return
	}
	if rec == nil || (s.clock != nil && rec.IsExpired(s.clock.Now())) {
		s.clearSessionCookie()
		return
	}

	subjectId := extensions.GetSubjectIdFromPrincipal(s.GetUser())
	if subjectId == "" || subjectId != rec.SubjectID {
		s.revokeOnSubjectChange(request.Context(), sessionID, rec, subjectId)
		s.clearSessionCookie()
		return
	}

	s.session = rec.SessionID
	s.clients = append([]string(nil), rec.ClientIDs...)
}

// SetSessionGrantRevoker makes the user session revoke the grants of the
// browser session it finds in the session cookie when a different subject
// signs in on that session: when a session is created, and when a request's
// authenticated subject does not match the session it carries. It takes
// effect only while server-side sessions are enabled; nil turns it off.
func (s *UserSession) SetSessionGrantRevoker(revoker *SessionGrantRevoker) {
	s.revoker = revoker
}

// revokeOnSubjectChange revokes the grants of the session sessionID, whose
// record is rec, when signing in newSubject changes its subject. A failure
// is logged by the revoker and does not reach the caller.
func (s *UserSession) revokeOnSubjectChange(ctx context.Context, sessionID string, rec *sessionpkg.Record, newSubject string) {
	if s.revoker == nil || sessionID == "" || sessionID == s.revokedSession {
		return
	}
	if !sessionSubjectChanged(rec, newSubject) {
		return
	}
	s.revokedSession = sessionID
	_ = s.revoker.Revoke(ctx, sessionID, rec.SubjectID)
}

// revokeBeforeSignIn applies revokeOnSubjectChange to the session the
// request's session cookie names, before principal signs in. An expired
// record still counts: its grants may outlive it. A missing record or a
// store failure revokes nothing; the failure is logged.
func (s *UserSession) revokeBeforeSignIn(ctx context.Context, principal *claims.ClaimsPrincipal) {
	if s.revoker == nil || !s.enabled || s.store == nil {
		return
	}
	sessionID := s.readSessionCookie()
	if sessionID == "" {
		return
	}
	rec, err := s.store.GetSession(ctx, sessionID)
	if err != nil {
		if !errors.Is(err, sessionpkg.ErrSessionNotFound) && s.logger != nil {
			// The error type only: the store's error text may repeat the
			// session id it was given.
			s.logger.Warn("create session: cannot load the former session", slog.String("errorType", fmt.Sprintf("%T", err)))
		}
		return
	}
	s.revokeOnSubjectChange(ctx, sessionID, rec, extensions.GetSubjectIdFromPrincipal(principal))
}

func (s *UserSession) CreateSessionId(ctx context.Context, principal *claims.ClaimsPrincipal, properties *auth.Properties) (string, error) {
	s.restoreDone = true
	s.revokeBeforeSignIn(ctx, principal)
	s.user = principal
	sessionId, err := utils.CreateUniqueId(32, utils.Hex)
	if err != nil {
		s.user = nil
		return "", fmt.Errorf("create session: generate session id: %w", err)
	}
	s.session = sessionId

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
		if err := s.store.CreateSession(ctx, rec); err != nil {
			s.session = ""
			s.user = nil
			return "", fmt.Errorf("create session: %w", err)
		}
		s.writeSessionCookie(s.session)
	}

	return s.session, nil
}

func (s *UserSession) GetSessionId() string {
	s.restore()
	return s.session
}

func (s *UserSession) GetClientList() ([]string, error) {
	s.restore()
	return append([]string(nil), s.clients...), nil
}

// GetUser returns the user established for the current request. When no session
// was created in this request, it restores the authenticated user from the
// authentication ticket via the default authenticate scheme's handler. It is a
// read-only recovery: no session is written and no cookie is emitted. A nil
// handler provider, absent default scheme, or empty result yields nil.
func (s *UserSession) GetUser() *claims.ClaimsPrincipal {
	if s.user != nil {
		return s.user
	}
	if s.handlerProvider == nil || s.schemes == nil {
		return nil
	}
	scheme := s.schemes.GetDefaultAuthenticateScheme()
	if scheme == nil {
		return nil
	}
	var request *http.Request
	var response http.ResponseWriter
	if s.accessor != nil {
		request = s.accessor.Request()
	}
	response = s.responseWriter()
	handler, err := s.handlerProvider.GetHandler(request, response, scheme.Name)
	if err != nil || handler == nil {
		return nil
	}
	result, err := handler.Authenticate()
	if err != nil || result == nil || result.None {
		return nil
	}
	return result.Principal
}

func (s *UserSession) AddClientId(ctx context.Context, clientId string) error {
	s.restore()
	if !utils.Contains(s.clients, clientId) {
		s.clients = append(s.clients, clientId)
	}

	if s.enabled && s.store != nil && s.session != "" {
		if err := s.store.AddClientID(ctx, s.session, clientId); err != nil && s.logger != nil {
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

type TokenService struct {
	claims        services.ClaimsService
	reference     storage.ReferenceTokenStore
	tokenCreation services.TokenCreationService
	clock         services.SystemClock
	keys          services.KeyMaterialService
	options       *config_options.WicketOptions
	logger        *slog.Logger
	request       *http.Request
	confirmation  services.AccessTokenConfirmation
}

// NewTokenService builds the token service. confirmation decides the
// confirmation of every access token serialized; nil leaves the
// confirmation a token model carries untouched.
func NewTokenService(
	claims services.ClaimsService,
	reference storage.ReferenceTokenStore,
	tokenCreation services.TokenCreationService,
	clock services.SystemClock,
	keys services.KeyMaterialService,
	options *config_options.WicketOptions,
	logger *slog.Logger,
	request *http.Request,
	confirmation services.AccessTokenConfirmation,
) *TokenService {
	return &TokenService{claims: claims, reference: reference, tokenCreation: tokenCreation, clock: clock, keys: keys, options: options, logger: logger, request: request, confirmation: confirmation}
}

func (s *TokenService) CreateAccessToken(ctx context.Context, request *responses_models.TokenCreationRequest) (*storage_models.Token, error) {
	tokenClaims := []*claims.Claim(nil)
	if request.Subject != nil {
		tokenClaims = request.Subject.Claims()
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
	// A session-bound access token carries the session id so downstream
	// validation can coordinate server-side session lifetime. Any session id
	// carried in from the subject's claims is dropped first so the token never
	// ends up with more than one, which would serialize as a JSON array.
	if request.ValidatedRequest != nil && request.ValidatedRequest.SessionId != "" {
		tokenClaims = append(
			utils.Where(tokenClaims, func(c *claims.Claim) bool { return c.Type != wicket.JwtClaimTypesSessionId }),
			claims.NewClaim(
				claims.WithClaimType(wicket.JwtClaimTypesSessionId),
				claims.WithClaimValue(request.ValidatedRequest.SessionId),
			),
		)
	}
	// The token itself names the requesting client and the granted scopes
	// (RFC 9068 §2.2); any same-typed claims carried in from the subject are
	// dropped first so each stays single-valued per grant.
	if request.ValidatedRequest != nil && request.ValidatedRequest.ClientId != "" {
		tokenClaims = append(
			utils.Where(tokenClaims, func(c *claims.Claim) bool { return c.Type != wicket.JwtClaimTypesClientId }),
			claims.NewClaim(
				claims.WithClaimType(wicket.JwtClaimTypesClientId),
				claims.WithClaimValue(request.ValidatedRequest.ClientId),
			),
		)
	}
	if request.ValidatedResources != nil {
		tokenClaims = utils.Where(tokenClaims, func(c *claims.Claim) bool { return c.Type != wicket.JwtClaimTypesScope })
		for _, scope := range request.ValidatedResources.RawScopeValues() {
			tokenClaims = append(tokenClaims, claims.NewClaim(
				claims.WithClaimType(wicket.JwtClaimTypesScope),
				claims.WithClaimValue(scope),
			))
		}
	}
	token := &storage_models.Token{CreationTime: s.clock.Now(), Type: wicket.TokenTypesAccessToken, Claims: tokenClaims, Audiences: audiences}
	if request.ValidatedRequest != nil {
		token.Issuer = request.ValidatedRequest.IssuerName
		token.Lifetime = request.ValidatedRequest.AccessTokenLifetime
		// The token names its client and the form that client is configured
		// to receive, so the serialization step can tell a self-contained
		// token from one kept server side.
		token.ClientId = request.ValidatedRequest.ClientId
		token.AccessTokenType = request.ValidatedRequest.AccessTokenType
	}
	return token, nil
}

func (s *TokenService) CreateIdentityToken(ctx context.Context, request *responses_models.TokenCreationRequest) (*storage_models.Token, error) {
	tokenClaims := []*claims.Claim(nil)
	if request.Subject != nil {
		tokenClaims = request.Subject.Claims()
	}
	appendClaim := func(claimType string, value string) {
		if value == "" {
			return
		}
		tokenClaims = append(
			utils.Where(tokenClaims, func(c *claims.Claim) bool { return c.Type != claimType }),
			claims.NewClaim(claims.WithClaimType(claimType), claims.WithClaimValue(value)),
		)
	}
	appendClaim(wicket.JwtClaimTypesNonce, request.Nonce)
	appendClaim(wicket.JwtClaimTypesStateHash, request.StateHash)
	// An identity token issued within a user session names that session
	// (OIDC Front-Channel and Back-Channel Logout: sid), so a relying party can
	// match a later logout notification to it. Anonymous requests carry none.
	if request.ValidatedRequest != nil {
		appendClaim(wicket.JwtClaimTypesSessionId, request.ValidatedRequest.SessionId)
	}
	if request.AccessTokenToHash != "" || request.AuthorizationCodeToHash != "" {
		algorithm, err := s.identitySigningAlgorithm(ctx, request)
		if err != nil {
			return nil, err
		}
		if request.AccessTokenToHash != "" {
			hash, err := utils.CreateHashClaimValue(request.AccessTokenToHash, algorithm)
			if err != nil {
				return nil, fmt.Errorf("create identity token: hash access token: %w", err)
			}
			appendClaim(wicket.JwtClaimTypesAccessTokenHash, hash)
		}
		if request.AuthorizationCodeToHash != "" {
			hash, err := utils.CreateHashClaimValue(request.AuthorizationCodeToHash, algorithm)
			if err != nil {
				return nil, fmt.Errorf("create identity token: hash authorization code: %w", err)
			}
			appendClaim(wicket.JwtClaimTypesAuthorizationCodeHash, hash)
		}
	}
	token := &storage_models.Token{CreationTime: s.clock.Now(), Type: wicket.TokenTypesIdentityToken, Claims: tokenClaims}
	if request.ValidatedRequest != nil {
		token.Issuer = request.ValidatedRequest.IssuerName
		// An identity token is addressed to the requesting client (OIDC Core
		// §2: aud MUST contain the relying party's client_id).
		if request.ValidatedRequest.ClientId != "" {
			token.Audiences = []string{request.ValidatedRequest.ClientId}
		}
		if request.ValidatedRequest.Client != nil {
			token.Lifetime = request.ValidatedRequest.Client.IdentityTokenLifetime
		}
	}
	return token, nil
}

// identitySigningAlgorithm resolves the algorithm the identity token will be
// signed with, which fixes the hash size of the derived at_hash/c_hash claims.
func (s *TokenService) identitySigningAlgorithm(ctx context.Context, request *responses_models.TokenCreationRequest) (string, error) {
	var allowed []string
	if request.ValidatedRequest != nil && request.ValidatedRequest.Client != nil {
		allowed = request.ValidatedRequest.Client.AllowedIdentityTokenSigningAlgorithms
	}
	credential, err := s.keys.GetSigningCredentials(ctx, allowed)
	if err != nil {
		return "", fmt.Errorf("create identity token: resolve signing credential: %w", err)
	}
	if credential == nil {
		return "", errors.New("create identity token: no signing credential available")
	}
	return credential.Algorithm, nil
}

func (s *TokenService) CreateSecurityToken(ctx context.Context, token *storage_models.Token) (string, error) {
	// Every access token is bound here, the one exit all of them share,
	// including the access token a refresh request reissues unchanged: the
	// binding always follows the certificate and the DPoP proof of the
	// current request.
	if token.Type == wicket.TokenTypesAccessToken && s.confirmation != nil {
		confirmation, err := s.confirmation.Confirmation(ctx, s.request, token.ClientId)
		if err != nil {
			return "", err
		}
		token.Confirmation = confirmation
	}
	// Only access tokens carry a jwt id, and only when the client opted in. Any
	// value carried in from an earlier assembly is dropped and replaced with a
	// freshly generated one so the id is never reused.
	if token.Type == wicket.TokenTypesAccessToken && token.IncludeJwtId {
		jwtId, err := utils.CreateUniqueId(16, utils.Base64Url)
		if err != nil {
			return "", fmt.Errorf("create security token: generate jwt id: %w", err)
		}
		token.Claims = append(
			utils.Where(token.Claims, func(c *claims.Claim) bool { return c.Type != wicket.JwtClaimTypesJwtId }),
			claims.NewClaim(
				claims.WithClaimType(wicket.JwtClaimTypesJwtId),
				claims.WithClaimValue(jwtId),
			),
		)
	}
	// Only an access token is ever handed out by reference; every other token
	// kind is a signed JWT whatever its access token type says.
	if token.Type == wicket.TokenTypesAccessToken && token.AccessTokenType == wicket.AccessTokenTypeReference {
		return s.createReferenceToken(ctx, token)
	}
	return s.tokenCreation.CreateToken(ctx, token)
}

// Fixed texts of the errors the reference token path reports. A handle is a
// credential and a store may echo the key it was given in its own error, so
// none of these texts varies with what a store returned.
const (
	referenceTokenMissingClientMessage   = "create security token: reference token names no client"
	referenceTokenMissingStoreMessage    = "create security token: reference token store is not available"
	referenceTokenDuplicateHandleMessage = "create security token: reference token handle already exists"
	referenceTokenStoreFailureMessage    = "create security token: reference token store write failed"
)

// referenceTokenStoreError reports a failed reference token write. Its text is
// fixed, while the store's own error stays reachable through errors.Is and
// errors.As.
type referenceTokenStoreError struct {
	message string
	cause   error
}

func (e *referenceTokenStoreError) Error() string { return e.message }

func (e *referenceTokenStoreError) Unwrap() error { return e.cause }

// createReferenceToken keeps the token server side under a freshly generated
// opaque handle and returns that handle. It fails closed: no handle is
// returned unless the store accepted the record, and no signed token is
// issued in its place.
func (s *TokenService) createReferenceToken(ctx context.Context, token *storage_models.Token) (string, error) {
	// Validation finds the owning client through this field; a record
	// without it could never be used.
	if token.ClientId == "" {
		return "", errors.New(referenceTokenMissingClientMessage)
	}
	if s.reference == nil {
		return "", errors.New(referenceTokenMissingStoreMessage)
	}
	handle, err := NewHandleGenerationService().Generate()
	if err != nil {
		return "", fmt.Errorf("create security token: generate reference token handle: %w", err)
	}
	if handle == "" {
		return "", errors.New("create security token: generate reference token handle: empty handle")
	}
	// The store receives its own copy: the caller keeps using its model after
	// this call, and a store is free to retain what it is given.
	stored := *token
	stored.Claims = append([]*claims.Claim(nil), token.Claims...)
	stored.Audiences = append([]string(nil), token.Audiences...)
	stored.AllowedSigningAlgorithms = append([]string(nil), token.AllowedSigningAlgorithms...)
	// Validation turns only the record's claims into token claims, so the
	// confirmation is also kept as a cnf claim of the stored copy.
	if strings.TrimSpace(token.Confirmation) != "" {
		var confirmation map[string]any
		if err := json.Unmarshal([]byte(token.Confirmation), &confirmation); err != nil || confirmation == nil {
			return "", errors.New("create security token: reference token confirmation is not a JSON object")
		}
		stored.Claims = append(
			utils.Where(stored.Claims, func(c *claims.Claim) bool { return c.Type != wicket.JwtClaimTypesConfirmation }),
			claims.NewClaim(
				claims.WithClaimType(wicket.JwtClaimTypesConfirmation),
				claims.WithClaimValue(confirmation),
			),
		)
	}
	if err := s.reference.StoreReferenceToken(ctx, handle, &stored); err != nil {
		message, category := referenceTokenStoreFailureMessage, "store_failure"
		if errors.Is(err, storage.ErrDuplicateHandle) {
			message, category = referenceTokenDuplicateHandleMessage, "duplicate_handle"
		}
		if s.logger != nil {
			// Neither the handle nor the store's error text is logged; the
			// store reports the detailed cause on its own side.
			s.logger.Error("Reference token could not be stored",
				slog.String("clientId", token.ClientId),
				slog.String("category", category),
				slog.String("errorType", fmt.Sprintf("%T", err)),
			)
		}
		return "", &referenceTokenStoreError{message: message, cause: err}
	}
	return handle, nil
}

type RefreshTokenService struct {
	store   storage.RefreshTokenStore
	handles services.HandleGenerationService

	// Consumption of one-time refresh tokens, see SetConsumption and
	// refresh_token_rotation.go. The zero value updates in place.
	consumption services.RefreshTokenConsumption
	clock       services.SystemClock
	logger      *slog.Logger

	// sessionBound records the issuing browser session on every refresh
	// token created, see SetSessionBinding.
	sessionBound bool
}

// SetSessionBinding declares whether a refresh token created from now on
// records the browser session its access token was issued in, so that the
// token can be revoked with that session. Off by default.
func (s *RefreshTokenService) SetSessionBinding(bound bool) {
	s.sessionBound = bound
}

func NewRefreshTokenService(store storage.RefreshTokenStore, handles services.HandleGenerationService) *RefreshTokenService {
	return &RefreshTokenService{store: store, handles: handles}
}

func (s *RefreshTokenService) CreateRefreshToken(ctx context.Context, request *responses_models.RefreshTokenCreationRequest) (string, error) {
	token := storage_models.NewRefreshToken()
	token.Subject = request.Subject
	token.ClientId = request.Client.ClientId
	token.Description = request.Description
	token.AuthorizedScopes = request.AuthorizedScopes
	token.AuthorizedResourceGaps = request.AuthorizedResourceGaps
	token.SetAccessToken(request.AccessToken, request.RequestedResourceGap)
	if s.sessionBound && request.AccessToken != nil {
		token.SessionId = request.AccessToken.SessionId()
	}
	// The refresh token of a public client is bound to the key of the DPoP
	// proof it was issued with, once and for good: a stolen token cannot be
	// redeemed without that key. A confidential client authenticates every
	// redemption and its refresh token stays unbound.
	if !request.Client.RequireClientSecret {
		token.DPoPKeyThumbprint = dpop.ProofThumbprint(ctx)
	}
	handle, err := s.handles.Generate()
	if err != nil {
		return "", fmt.Errorf("create refresh token: generate handle: %w", err)
	}
	if err := s.store.StoreRefreshToken(ctx, handle, token); err != nil {
		return "", err
	}
	return handle, nil
}

func (s *RefreshTokenService) UpdateRefreshToken(ctx context.Context, request *responses_models.RefreshTokenUpdateRequest) (string, error) {
	if s.rotates(request) {
		return s.rotate(ctx, request)
	}
	expected := 0
	if request.RefreshToken != nil {
		expected = request.RefreshToken.Version
	}
	if request.RefreshToken != nil && request.AccessToken != nil {
		request.RefreshToken.SetAccessToken(request.AccessToken, request.RequestedResourceGap)
	}
	return request.Handle, s.store.UpdateRefreshToken(ctx, request.Handle, request.RefreshToken, expected)
}

func (s *RefreshTokenService) ValidateRefreshToken(ctx context.Context, handle string, client *storage_models.Client) *validators_models.TokenValidationResult {
	token, err := s.store.GetRefreshToken(ctx, handle)
	result := validators_models.NewTokenValidationResult()
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			result.Error = fmt.Errorf("refresh token not found: %w", storage.ErrNotFound)
			return result
		}
		result.Error = fmt.Errorf("validate refresh token: %w", err)
		return result
	}
	if token.ConsumedTime != nil {
		result.Error = s.refuseConsumed(ctx, handle, token, client)
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

func (s *PersistedGrantService) RemoveAllGrantsAsync(ctx context.Context, subjectId, clientId, sessionId string) error {
	return s.store.RemoveAll(ctx, &storage.PersistedGrantFilter{SubjectId: subjectId, ClientId: clientId, SessionId: sessionId})
}

type HandleGenerationService struct{}

func NewHandleGenerationService() HandleGenerationService { return HandleGenerationService{} }
func (HandleGenerationService) Generate() (string, error) { return utils.CreateUniqueId(32, utils.Hex) }

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

func (s *DeviceFlowCodeService) StoreDeviceAuthorization(ctx context.Context, userCode string, data *storage_models.DeviceCode) (string, error) {
	deviceCode, err := s.handles.Generate()
	if err != nil {
		return "", fmt.Errorf("store device authorization: generate device code: %w", err)
	}
	return deviceCode, s.store.StoreDeviceAuthorization(ctx, deviceCode, userCode, data)
}
func (s *DeviceFlowCodeService) FindByUserCode(ctx context.Context, userCode string) (*storage_models.DeviceCode, error) {
	return s.store.FindByUserCode(ctx, userCode)
}
func (s *DeviceFlowCodeService) FindByDeviceCode(ctx context.Context, deviceCode string) (*storage_models.DeviceCode, error) {
	return s.store.FindByDeviceCode(ctx, deviceCode)
}
func (s *DeviceFlowCodeService) UpdateByUserCode(ctx context.Context, userCode string, data *storage_models.DeviceCode) error {
	return s.store.UpdateByUserCode(ctx, userCode, data)
}
func (s *DeviceFlowCodeService) RemoveByDeviceCode(ctx context.Context, deviceCode string) error {
	return s.store.RemoveByDeviceCode(ctx, deviceCode)
}

type ConsentService struct{}

func NewConsentService() ConsentService { return ConsentService{} }

// RequiresConsent reports whether an explicit consent decision is required for the
// requested scopes. It currently honors only the client's RequireConsent flag;
// remembered-grant lookup against the consent store is not yet wired and lands with
// the authorize endpoint pipeline.
func (ConsentService) RequiresConsent(subject *claims.ClaimsPrincipal, client *storage_models.Client, parsedScopes []*validators_models.ParsedScopeValue) (bool, error) {
	if client == nil {
		return false, nil
	}
	return client.RequireConsent, nil
}

// UpdateConsent persists a remembered consent decision. Store-backed persistence is
// not yet wired and lands with the authorize endpoint pipeline.
func (ConsentService) UpdateConsent(subject *claims.ClaimsPrincipal, client *storage_models.Client, parsedScopes []*validators_models.ParsedScopeValue) error {
	return nil
}

func (ConsentService) GrantConsent(*messages.AuthorizationRequest, *messages.ConsentResponse, string) error {
	return nil
}
func (ConsentService) DenyAuthorization(*messages.AuthorizationRequest, string) error { return nil }

type InteractionService struct {
	consent       services.ConsentService
	logout        storage.MessageStore[messages.LogoutMessage]
	errors        storage.MessageStore[messages.ErrorMessage]
	consentStore  storage.ConsentMessageStore
	user          services.UserSession
	parser        *ReturnUrlParser
	clock         services.SystemClock
	urls          services.ServerUrls
	notifications storage.MessageStore[contexts.LogoutNotificationContext]
}

func NewInteractionService(clock services.SystemClock, logout storage.MessageStore[messages.LogoutMessage], errors storage.MessageStore[messages.ErrorMessage], consentStore storage.ConsentMessageStore, grants services.PersistedGrantService, user services.UserSession, logger *slog.Logger, parser *ReturnUrlParser, urls services.ServerUrls, notifications storage.MessageStore[contexts.LogoutNotificationContext]) *InteractionService {
	return &InteractionService{
		consent:       NewConsentService(),
		logout:        logout,
		errors:        errors,
		consentStore:  consentStore,
		user:          user,
		parser:        parser,
		clock:         clock,
		urls:          urls,
		notifications: notifications,
	}
}

func (s *InteractionService) GetAuthorizationContext(ctx context.Context, returnUrl string) (*messages.AuthorizationRequest, error) {
	if s.parser == nil {
		return nil, nil
	}
	return s.parser.Parse(ctx, returnUrl)
}
func (s *InteractionService) GetLogoutContext(ctx context.Context, logoutId string) (*messages.LogoutRequest, error) {
	if s.logout == nil || logoutId == "" {
		return messages.NewLogoutRequest("", nil), nil
	}
	message, err := s.logout.Read(ctx, logoutId)
	if err != nil || message == nil {
		return messages.NewLogoutRequest("", nil), err
	}
	iframeUrl, err := s.signOutIframeUrl(ctx, message.Data)
	if err != nil {
		return nil, err
	}
	return messages.NewLogoutRequest(iframeUrl, message.Data), nil
}

// signOutIframeUrl publishes the front-channel notification context for an
// authenticated sign-out and returns the callback iframe address carrying its
// handle. A logout without a session or without client participation has no
// front-channel work, so no iframe is offered.
func (s *InteractionService) signOutIframeUrl(ctx context.Context, logout *messages.LogoutMessage) (string, error) {
	if logout == nil || s.notifications == nil || s.urls == nil {
		return "", nil
	}
	if logout.SessionId == "" || len(logout.ClientIds) == 0 {
		return "", nil
	}

	context := contexts.LogoutNotificationContext{
		SubjectId: logout.SubjectId,
		SessionId: logout.SessionId,
		ClientIds: logout.ClientIds,
	}
	handle, err := s.notifications.Write(ctx, messages.NewMessageWithCreated(&context, s.clock.Now().Unix()))
	if err != nil {
		return "", fmt.Errorf("write end-session notification: %w", err)
	}

	callback := strings.TrimRight(s.urls.BaseUrl(), "/") + utils.EnsureLeadingSlash(wicket.ProtocolRoutePathsEndSessionCallback)
	return utils.AddQuery(callback, wicket.UIConstantsDefaultRoutePathParamsEndSessionCallback, handle), nil
}
func (s *InteractionService) GetErrorContext(ctx context.Context, errorId string) (*messages.ErrorMessage, error) {
	if s.errors == nil || errorId == "" {
		return messages.NewErrorMessage(), nil
	}
	message, err := s.errors.Read(ctx, errorId)
	if err != nil || message == nil || message.Data == nil {
		return messages.NewErrorMessage(), err
	}
	return message.Data, nil
}

// GrantConsent records the consent answer under the key the authorize callback
// derives from the subject and the original request parameters, so the callback
// can pick the answer up and complete the flow.
func (s *InteractionService) GrantConsent(ctx context.Context, request *messages.AuthorizationRequest, response *messages.ConsentResponse, subject string) error {
	if s.consentStore == nil || request == nil {
		return s.consent.GrantConsent(request, response, subject)
	}
	subjectId := subject
	if subjectId == "" && s.user != nil {
		subjectId = extensions.GetSubjectIdFromPrincipal(s.user.GetUser())
	}
	key := storage.ConsentMessageKey(subjectId, request.Parameters)
	message := messages.NewMessage(response)
	if s.clock != nil {
		message.Created = s.clock.Now().Unix()
	}
	return s.consentStore.Write(ctx, key, message)
}

func (s *InteractionService) DenyAuthorization(ctx context.Context, request *messages.AuthorizationRequest, subject string) error {
	return s.consent.DenyAuthorization(request, subject)
}
