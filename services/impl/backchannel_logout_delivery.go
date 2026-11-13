// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/claims"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/extensions"
	"github.com/gonewx/wicket/models/contexts"
	"github.com/gonewx/wicket/services"
	sessionpkg "github.com/gonewx/wicket/session"
	"github.com/gonewx/wicket/storage"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/utils"
)

const (
	// TokenTypesLogoutToken is the token type of an OIDC Back-Channel Logout
	// logout token.
	TokenTypesLogoutToken = "logout_token"

	// LogoutTokenJwtType is the JOSE typ header of a logout token
	// (OIDC Back-Channel Logout 1.0 §2.4, §4.1).
	LogoutTokenJwtType = "logout+jwt"

	// LogoutTokenLifetimeSeconds keeps logout tokens short-lived: the
	// specification recommends no more than two minutes (§4).
	LogoutTokenLifetimeSeconds = 120

	// BackChannelLogoutTimeout bounds one round of back-channel logout
	// delivery, and is the timeout of the default HTTP client used to post
	// logout tokens.
	BackChannelLogoutTimeout = 5 * time.Second

	// BackChannelLogoutEventType names the logout event inside the events
	// claim of a logout token.
	BackChannelLogoutEventType = "http://schemas.openid.net/event/backchannel-logout"
)

// BackchannelLogoutService delivers OIDC Back-Channel Logout notifications.
// It delivers only when server-side sessions and the check-session endpoint are
// both enabled: only then does the provider remember which clients a session
// signed in to, and only then do identity tokens carry the session id a logout
// token refers to. A logout context is checked against the session store
// before anything is sent: the session must exist and be current, the subject
// must match, and only clients recorded for the session are notified; the
// logout token's subject is the session's subject.
//
// For every remaining client that registered a back-channel logout URI it
// signs a logout token and posts it to that pre-registered URI. Tokens
// are signed sequentially on the calling goroutine (the issuer name and client
// lookups are request bound); the posts then run concurrently and the call
// waits for them up to a fixed bound. A failing relying party is only logged:
// it never blocks the user's logout nor the delivery to other relying parties.
type BackchannelLogoutService struct {
	notifications services.LogoutNotificationService
	client        services.BackChannelLogoutHttpClient
	tokens        services.TokenCreationService
	clients       storage.ClientStore
	issuer        services.IssuerNameService
	sessions      sessionpkg.Store
	clock         services.SystemClock
	options       *config_options.WicketOptions
	logger        *slog.Logger

	// timeout bounds a whole delivery round: signing and waiting for posts.
	timeout time.Duration
}

func NewBackchannelLogoutService(
	notifications services.LogoutNotificationService,
	client services.BackChannelLogoutHttpClient,
	tokens services.TokenCreationService,
	clients storage.ClientStore,
	issuer services.IssuerNameService,
	sessions sessionpkg.Store,
	clock services.SystemClock,
	options *config_options.WicketOptions,
	logger *slog.Logger,
) *BackchannelLogoutService {
	return &BackchannelLogoutService{
		notifications: notifications,
		client:        client,
		tokens:        tokens,
		clients:       clients,
		issuer:        issuer,
		sessions:      sessions,
		clock:         clock,
		options:       options,
		logger:        logger,
		timeout:       BackChannelLogoutTimeout,
	}
}

// DeliversBackChannelLogout reports whether this assembly delivers logout
// notifications, which decides whether discovery advertises back-channel
// logout support: server-side sessions and the check-session endpoint must
// both be enabled.
func (s *BackchannelLogoutService) DeliversBackChannelLogout() bool {
	return s != nil && s.options != nil &&
		s.options.ServerSideSessions != nil && s.options.ServerSideSessions.Enabled &&
		s.options.Endpoints != nil && s.options.Endpoints.EnableCheckSessionEndpoint
}

// backChannelLogoutDelivery is one signed logout token ready to be posted.
type backChannelLogoutDelivery struct {
	clientId  string
	logoutUri string
	token     string
}

// SendLogoutNotificationsAsync signs and posts a logout token to every
// participating client with a registered back-channel logout URI. Delivery
// failures are logged and never returned.
func (s *BackchannelLogoutService) SendLogoutNotificationsAsync(notification *contexts.LogoutNotificationContext) error {
	if s == nil || notification == nil || len(notification.ClientIds) == 0 {
		return nil
	}
	if !s.DeliversBackChannelLogout() || s.notifications == nil || s.client == nil {
		return nil
	}

	// The request context is deliberately not used: a browser abandoning the
	// callback iframe must not cancel delivery.
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	verified, ok := s.verify(ctx, notification)
	if !ok {
		return nil
	}

	requests, err := s.notifications.GetBackchannelLogoutNotifications(ctx, verified)
	if err != nil {
		s.log().Warn("back-channel logout: cannot build notifications", slog.String("error", err.Error()))
		return nil
	}

	deliveries := s.prepare(ctx, requests, verified.SubjectId)
	if len(deliveries) == 0 {
		return nil
	}
	s.post(ctx, deliveries)
	return nil
}

// verify checks the logout context against the session store and returns a
// narrowed copy of it: the session must exist and be current, a subject named
// by the context must be the session's subject, and only clients recorded for
// the session remain. The copy's subject is the session's subject. The
// caller's context is left untouched.
func (s *BackchannelLogoutService) verify(ctx context.Context, notification *contexts.LogoutNotificationContext) (*contexts.LogoutNotificationContext, bool) {
	if notification.SessionId == "" {
		s.log().Warn("back-channel logout: skipped, logout context names no session")
		return nil, false
	}
	if s.sessions == nil {
		s.log().Warn("back-channel logout: skipped, no session store")
		return nil, false
	}
	record, err := s.sessions.GetSession(ctx, notification.SessionId)
	if err != nil && !errors.Is(err, sessionpkg.ErrSessionNotFound) {
		s.log().Warn("back-channel logout: skipped, cannot read the session", slog.String("error", err.Error()))
		return nil, false
	}
	if err != nil || record == nil {
		s.log().Warn("back-channel logout: skipped, logout context names an unknown session")
		return nil, false
	}
	if s.clock != nil && record.IsExpired(s.clock.Now()) {
		s.log().Warn("back-channel logout: skipped, logout context names an expired session")
		return nil, false
	}
	if notification.SubjectId != "" && notification.SubjectId != record.SubjectID {
		s.log().Warn("back-channel logout: skipped, logout context subject does not match the session")
		return nil, false
	}

	clientIds := make([]string, 0, len(notification.ClientIds))
	for _, clientId := range notification.ClientIds {
		if utils.Contains(record.ClientIDs, clientId) && !utils.Contains(clientIds, clientId) {
			clientIds = append(clientIds, clientId)
		}
	}
	if len(clientIds) == 0 {
		s.log().Warn("back-channel logout: skipped, no client of the logout context is recorded for the session")
		return nil, false
	}
	// An issuer named by the logout context cannot be verified against the
	// session and is not carried over: logout tokens are issued under the
	// current issuer.
	return &contexts.LogoutNotificationContext{
		SubjectId: record.SubjectID,
		SessionId: notification.SessionId,
		ClientIds: clientIds,
	}, true
}

// prepare validates each request and signs its logout token. Everything that
// touches request-bound services happens here, before any goroutine starts.
// The logout token's subject is always the verified session's subject.
func (s *BackchannelLogoutService) prepare(ctx context.Context, requests []*services.BackchannelLogoutRequest, subjectId string) []backChannelLogoutDelivery {
	defaultIssuer := ""
	defaultIssuerResolved := false
	deliveries := make([]backChannelLogoutDelivery, 0, len(requests))
	for _, request := range requests {
		if request == nil {
			continue
		}
		verified := *request
		verified.SubjectId = subjectId
		request = &verified
		if !s.acceptable(request) {
			continue
		}

		issuer := request.Issuer
		if issuer == "" {
			if !defaultIssuerResolved {
				defaultIssuerResolved = true
				if s.issuer != nil {
					defaultIssuer = s.issuer.GetCurrent()
				}
			}
			issuer = defaultIssuer
		}
		if issuer == "" {
			s.log().Warn("back-channel logout: skipped, no issuer", slog.String("client_id", request.ClientId))
			continue
		}

		token, err := s.sign(ctx, request, issuer)
		if err != nil {
			s.log().Warn("back-channel logout: skipped, cannot create logout token",
				slog.String("client_id", request.ClientId), slog.String("error", err.Error()))
			continue
		}
		deliveries = append(deliveries, backChannelLogoutDelivery{
			clientId:  request.ClientId,
			logoutUri: request.LogoutUri,
			token:     token,
		})
	}
	return deliveries
}

// acceptable reports whether a logout token may be sent for the request: the
// logout URI must be an absolute http(s) URI without fragment, the token must
// identify the subject or the session, and a client requiring the session id
// must get one.
func (s *BackchannelLogoutService) acceptable(request *services.BackchannelLogoutRequest) bool {
	if !validBackChannelLogoutUri(request.LogoutUri) {
		s.log().Warn("back-channel logout: skipped, invalid logout uri", slog.String("client_id", request.ClientId))
		return false
	}
	if request.SubjectId == "" && request.SessionId == "" {
		s.log().Warn("back-channel logout: skipped, neither subject nor session id", slog.String("client_id", request.ClientId))
		return false
	}
	if request.SessionIdRequired && request.SessionId == "" {
		s.log().Warn("back-channel logout: skipped, client requires a session id", slog.String("client_id", request.ClientId))
		return false
	}
	if strings.EqualFold(schemeOf(request.LogoutUri), "http") {
		s.log().Debug("back-channel logout: logout uri is not https", slog.String("client_id", request.ClientId))
	}
	s.log().Debug("back-channel logout: target", slog.String("client_id", request.ClientId), slog.String("logout_uri", request.LogoutUri))
	return true
}

func validBackChannelLogoutUri(raw string) bool {
	if raw == "" || strings.Contains(raw, "#") {
		return false
	}
	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() || parsed.Hostname() == "" {
		return false
	}
	scheme := strings.ToLower(parsed.Scheme)
	return scheme == "http" || scheme == "https"
}

func schemeOf(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return parsed.Scheme
}

// sign builds and signs the logout token for one relying party. Its claim set
// is exactly iss, aud, iat, exp (plus nbf from the shared payload builder),
// jti, events and the available sub / sid; it never carries a nonce. The
// client is looked up again so the token follows the client's identity token
// signing algorithms.
func (s *BackchannelLogoutService) sign(ctx context.Context, request *services.BackchannelLogoutRequest, issuer string) (string, error) {
	if s.tokens == nil || s.clients == nil {
		return "", fmt.Errorf("logout token signing is not configured")
	}
	client, err := extensions.FindEnabledClientById(ctx, s.clients, request.ClientId)
	if err != nil {
		return "", fmt.Errorf("find enabled client: %w", err)
	}
	if client == nil {
		return "", fmt.Errorf("find enabled client: %w", storage.ErrNotFound)
	}

	jti, err := utils.CreateUniqueId(32, utils.Hex)
	if err != nil {
		return "", fmt.Errorf("create jwt id: %w", err)
	}
	tokenClaims := []*claims.Claim{
		claims.NewClaim(claims.WithClaimType(wicket.JwtClaimTypesJwtId), claims.WithClaimValue(jti)),
		claims.NewClaim(
			claims.WithClaimType(wicket.JwtClaimTypesEvents),
			claims.WithClaimValue(map[string]any{BackChannelLogoutEventType: map[string]any{}}),
		),
	}
	if request.SubjectId != "" {
		tokenClaims = append(tokenClaims, claims.NewClaim(
			claims.WithClaimType(wicket.JwtClaimTypesSubject), claims.WithClaimValue(request.SubjectId)))
	}
	if request.SessionId != "" {
		tokenClaims = append(tokenClaims, claims.NewClaim(
			claims.WithClaimType(wicket.JwtClaimTypesSessionId), claims.WithClaimValue(request.SessionId)))
	}

	token := &storage_models.Token{
		Type:                     TokenTypesLogoutToken,
		Issuer:                   issuer,
		Audiences:                []string{request.ClientId},
		Lifetime:                 LogoutTokenLifetimeSeconds,
		AllowedSigningAlgorithms: client.AllowedIdentityTokenSigningAlgorithms,
		Claims:                   tokenClaims,
	}
	signed, err := s.tokens.CreateToken(ctx, token)
	if err != nil {
		return "", fmt.Errorf("sign logout token: %w", err)
	}
	return signed, nil
}

// post sends every logout token concurrently and waits for the posts until ctx
// expires. Posts still running at that point are left to the HTTP client's own
// timeout.
func (s *BackchannelLogoutService) post(ctx context.Context, deliveries []backChannelLogoutDelivery) {
	var (
		mu      sync.Mutex
		pending = make(map[int]string, len(deliveries))
		wg      sync.WaitGroup
	)
	for i, delivery := range deliveries {
		pending[i] = delivery.clientId
	}

	for i, delivery := range deliveries {
		wg.Add(1)
		go func(i int, delivery backChannelLogoutDelivery) {
			defer wg.Done()
			defer func() {
				mu.Lock()
				delete(pending, i)
				mu.Unlock()
			}()
			defer func() {
				if recovered := recover(); recovered != nil {
					s.log().Warn("back-channel logout: delivery panicked", slog.String("client_id", delivery.clientId))
				}
			}()
			if err := s.client.Post(delivery.logoutUri, url.Values{"logout_token": {delivery.token}}); err != nil {
				s.log().Warn("back-channel logout: delivery failed",
					slog.String("client_id", delivery.clientId), slog.String("error", err.Error()))
			}
		}(i, delivery)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
		mu.Lock()
		unfinished := make([]string, 0, len(pending))
		for _, clientId := range pending {
			unfinished = append(unfinished, clientId)
		}
		mu.Unlock()
		sort.Strings(unfinished)
		s.log().Warn("back-channel logout: delivery still running at the wait bound",
			slog.Any("client_ids", unfinished))
	}
}

func (s *BackchannelLogoutService) log() *slog.Logger {
	if s.logger != nil {
		return s.logger
	}
	return slog.Default()
}
