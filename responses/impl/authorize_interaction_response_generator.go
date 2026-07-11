// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"log/slog"
	"time"

	"github.com/gonewx/wicket"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/extensions"
	"github.com/gonewx/wicket/models/contexts"
	"github.com/gonewx/wicket/models/messages"
	responses_models "github.com/gonewx/wicket/responses/models"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/utils"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// AuthorizeInteractionResponseGenerator classifies the interaction an authorize
// request still needs before an authorization response can be issued.
// input: validated authorize request/consent -> behavior: decide login vs consent
// vs silent-failure -> output: interaction response.
type AuthorizeInteractionResponseGenerator struct {
	logger  *slog.Logger
	clock   services.SystemClock
	options *config_options.WicketOptions
	consent services.ConsentService
	profile services.ProfileService
	urls    services.ServerUrls
	store   storage.AuthorizationParametersMessageStore

	// loginHandler and consentHandler are the substitutable stages Handle composes.
	// They default to this generator's own methods; a caller may replace either to
	// contribute a custom interaction result, which Handle then classifies.
	loginHandler   func(*validators_models.ValidatedAuthorizeRequest) *responses_models.InteractionResponse
	consentHandler func(*validators_models.ValidatedAuthorizeRequest, *messages.ConsentResponse) *responses_models.InteractionResponse
}

func NewAuthorizeInteractionResponseGenerator(
	logger *slog.Logger,
	clock services.SystemClock,
	options *config_options.WicketOptions,
	consent services.ConsentService,
	profile services.ProfileService,
	urls services.ServerUrls,
	store storage.AuthorizationParametersMessageStore,
) *AuthorizeInteractionResponseGenerator {
	g := &AuthorizeInteractionResponseGenerator{
		logger:  logger,
		clock:   clock,
		options: options,
		consent: consent,
		profile: profile,
		urls:    urls,
		store:   store,
	}
	g.loginHandler = g.HandleLogin
	g.consentHandler = g.HandleConsent
	return g
}

// Handle composes the login and consent stages. Under prompt=none any interaction
// the stages would demand is turned into the matching standard error instead.
func (g *AuthorizeInteractionResponseGenerator) Handle(req *validators_models.ValidatedAuthorizeRequest, consent *messages.ConsentResponse) *responses_models.InteractionResponse {
	login := g.loginHandler(req)
	if promptNone(req) {
		if login.IsRedirect() {
			return &responses_models.InteractionResponse{Error: gois.AuthorizeErrorsInteractionRequired}
		}
		if login.IsLogin {
			return &responses_models.InteractionResponse{Error: gois.AuthorizeErrorsLoginRequired}
		}
	}
	if login.IsLogin || login.IsError() || login.IsRedirect() {
		return login
	}

	result := g.consentHandler(req, consent)
	if promptNone(req) && result.IsConsent {
		return &responses_models.InteractionResponse{Error: gois.AuthorizeErrorsConsentRequired}
	}
	return result
}

// HandleLogin reports whether the request still needs an interactive login. The
// prompt and unauthenticated checks come first, before any client field is read,
// because those requests may carry no client.
func (g *AuthorizeInteractionResponseGenerator) HandleLogin(req *validators_models.ValidatedAuthorizeRequest) *responses_models.InteractionResponse {
	// an explicit login/select_account prompt forces re-authentication; the prompt
	// is suppressed so the follow-up request does not trigger it again.
	if utils.Contains(req.PromptModes, gois.PromptModesLogin) || utils.Contains(req.PromptModes, gois.PromptModesSelectAccount) {
		req.RemovePrompt()
		return &responses_models.InteractionResponse{IsLogin: true}
	}

	// an unauthenticated subject must log in.
	if !extensions.ClaimsPrincipalIsAuthenticated(req.Subject) {
		return &responses_models.InteractionResponse{IsLogin: true}
	}

	// an inactive subject must re-authenticate.
	if !g.subjectActive(req) {
		return &responses_models.InteractionResponse{IsLogin: true}
	}

	currentIdp := extensions.GetIdentityProviderFromPrincipal(req.Subject)

	// a specific identity provider was requested via acr and differs from the one
	// the current session was established with.
	if requested := req.GetIdP(); requested != "" && requested != currentIdp {
		return &responses_models.InteractionResponse{IsLogin: true}
	}

	// the session is older than the request's maximum authentication age. a
	// max_age of zero demands a fresh authentication, so any elapsed session fails.
	if req.MaxAge != nil && g.sessionAge(req) > time.Duration(*req.MaxAge)*time.Second {
		return &responses_models.InteractionResponse{IsLogin: true}
	}

	// a locally established session against a client that disables local login.
	if currentIdp == gois.LocalIdentityProvider && req.Client != nil && !req.Client.EnableLocalLogin {
		return &responses_models.InteractionResponse{IsLogin: true}
	}

	// the current identity provider is not in the client's allow list.
	if req.Client != nil && len(req.Client.IdentityProviderRestrictions) > 0 &&
		!utils.Contains(req.Client.IdentityProviderRestrictions, currentIdp) {
		return &responses_models.InteractionResponse{IsLogin: true}
	}

	// the session is older than the client's single-sign-on lifetime.
	if req.Client != nil && req.Client.UserSsoLifetime > 0 &&
		g.sessionAge(req) > time.Duration(req.Client.UserSsoLifetime)*time.Second {
		return &responses_models.InteractionResponse{IsLogin: true}
	}

	return &responses_models.InteractionResponse{IsLogin: false}
}

// HandleConsent decides whether the request needs a consent interaction and, once
// the user has answered, whether the grant is acceptable.
func (g *AuthorizeInteractionResponseGenerator) HandleConsent(req *validators_models.ValidatedAuthorizeRequest, consent *messages.ConsentResponse) *responses_models.InteractionResponse {
	if req == nil {
		return &responses_models.InteractionResponse{Error: gois.ArgumentNullException}
	}

	// consent handling accepts only a consent-class prompt; a login-class prompt
	// reaching here is a misdirected request.
	if utils.Contains(req.PromptModes, gois.PromptModesLogin) || utils.Contains(req.PromptModes, gois.PromptModesSelectAccount) {
		return &responses_models.InteractionResponse{Error: gois.InvalidOperationException}
	}

	consentRequired := utils.Contains(req.PromptModes, gois.PromptModesConsent)
	if !consentRequired {
		required, err := g.consent.RequiresConsent(req.Subject, req.Client, req.ValidatedResources.ParsedScopes)
		if err != nil {
			return &responses_models.InteractionResponse{Error: err}
		}
		consentRequired = required
	}

	if !consentRequired {
		return responses_models.NewInteractionResponse()
	}

	// consent is required; prompt=none cannot present the page.
	if promptNone(req) {
		return &responses_models.InteractionResponse{Error: gois.AuthorizeErrorsConsentRequired}
	}

	// the user has not answered yet; present the consent page.
	if consent == nil {
		return &responses_models.InteractionResponse{IsConsent: true}
	}

	// an answer was submitted.
	req.WasConsentShown = true

	if !consent.Granted() {
		return &responses_models.InteractionResponse{Error: gois.AuthorizeErrorsAccessDenied}
	}

	for _, required := range req.ValidatedResources.GetRequiredScopeValues() {
		if !utils.Contains(consent.ScopesValuesConsented, required) {
			return &responses_models.InteractionResponse{Error: gois.AuthorizeErrorsAccessDenied}
		}
	}

	granted := req.ValidatedResources.Filter(consent.ScopesValuesConsented)

	if req.Client != nil && req.Client.AllowRememberConsent {
		var remembered []*validators_models.ParsedScopeValue
		if consent.RememberConsent {
			remembered = granted.ParsedScopes
		}
		// a failure to persist the remembered decision does not invalidate this
		// grant; the user is simply asked to consent again next time, so we log
		// and continue rather than failing the authorization.
		if err := g.consent.UpdateConsent(req.Subject, req.Client, remembered); err != nil {
			g.logger.Warn("persisting remembered consent failed", "err", err)
		}
	}

	req.ValidatedResources = granted
	return &responses_models.InteractionResponse{IsConsent: false}
}

// subjectActive reports whether the profile service still considers the subject
// active for this client.
func (g *AuthorizeInteractionResponseGenerator) subjectActive(req *validators_models.ValidatedAuthorizeRequest) bool {
	ctx := contexts.NewIsActiveContext(req.Subject, req.Client, gois.ProfileIsActiveCallersAuthorizeEndpoint)
	g.profile.IsActive(ctx)
	return ctx.IsActive
}

// sessionAge is the elapsed time since the subject last authenticated.
func (g *AuthorizeInteractionResponseGenerator) sessionAge(req *validators_models.ValidatedAuthorizeRequest) time.Duration {
	return g.clock.Now().Sub(extensions.GetAuthenticationTime(req.Subject))
}

func promptNone(req *validators_models.ValidatedAuthorizeRequest) bool {
	return utils.Contains(req.PromptModes, gois.PromptModesNone)
}
