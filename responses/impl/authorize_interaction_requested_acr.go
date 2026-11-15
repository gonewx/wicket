// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"slices"
	"strings"

	"github.com/gonewx/wicket"
	responses_models "github.com/gonewx/wicket/responses/models"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// unmetRequestedAcrDescription is the error_description sent with
// unmet_authentication_requirements.
const unmetRequestedAcrDescription = "requested acr_values could not be satisfied"

// RequireRequestedAcr makes Handle enforce the acr_values of a request: the
// session's acr claim must be one of the requested values. A session that
// does not satisfy the request is sent to the login page once; when it still
// does not satisfy it afterwards, or the request carries prompt=none, Handle
// returns unmet_authentication_requirements.
func (g *AuthorizeInteractionResponseGenerator) RequireRequestedAcr() {
	g.requestedAcrRequired = true
}

// requestedAcrValues are the acr_values of req that name an authentication
// class: empty values and the identity provider and tenant hints are left
// out.
func requestedAcrValues(req *validators_models.ValidatedAuthorizeRequest) []string {
	var values []string
	for _, value := range req.AuthenticationContextReferenceClasses {
		if value == "" || slices.ContainsFunc(wicket.KnownAcrValuesAll, func(prefix string) bool { return strings.HasPrefix(value, prefix) }) {
			continue
		}
		values = append(values, value)
	}
	return values
}

// sessionAcr is the first acr claim of the subject, or the empty string.
func sessionAcr(req *validators_models.ValidatedAuthorizeRequest) string {
	claim := req.Subject.FindFirst(wicket.JwtClaimTypesAuthenticationContextClassReference)
	if claim == nil {
		return ""
	}
	value, _ := claim.Value.(string)
	return value
}

// requestedAcrSatisfied reports whether the session satisfies the requested
// acr_values: none were requested, or the session's acr is one of them.
func requestedAcrSatisfied(req *validators_models.ValidatedAuthorizeRequest) bool {
	requested := requestedAcrValues(req)
	return len(requested) == 0 || slices.Contains(requested, sessionAcr(req))
}

// markRequestedAcrLogin records that this authorization has been through an
// interactive login by adding login to the suppressed prompt values, unless
// it is there already. The values already suppressed are kept in order.
func markRequestedAcrLogin(req *validators_models.ValidatedAuthorizeRequest) {
	if slices.Contains(req.SuppressedPromptModes, wicket.PromptModesLogin) {
		return
	}
	var suppressed []string
	// a value the validator would refuse on return would cost the marker, so
	// only suppressible prompt values are kept: the supported ones and
	// create, but never none.
	add := func(value string) {
		suppressible := value == wicket.PromptModesCreate ||
			(value != wicket.PromptModesNone && slices.Contains(wicket.SupportedPromptModes, value))
		if suppressible && !slices.Contains(suppressed, value) {
			suppressed = append(suppressed, value)
		}
	}
	for _, value := range req.SuppressedPromptModes {
		add(value)
	}
	if req.Raw != nil {
		for _, entry := range req.Raw[wicket.SuppressedPrompt] {
			for _, value := range strings.Fields(entry) {
				add(value)
			}
		}
	}
	add(wicket.PromptModesLogin)
	req.SuppressedPromptModes = suppressed
	if req.Raw != nil {
		req.Raw.Set(wicket.SuppressedPrompt, strings.Join(suppressed, " "))
	}
}

// handleRequestedAcrLogin marks a login interaction of a request listing
// acr_values, so the returning request is known to have been through it.
func (g *AuthorizeInteractionResponseGenerator) handleRequestedAcrLogin(req *validators_models.ValidatedAuthorizeRequest) {
	if !g.requestedAcrRequired || promptNone(req) || len(requestedAcrValues(req)) == 0 {
		return
	}
	markRequestedAcrLogin(req)
}

// handleRequestedAcr checks the requested acr_values of a request that needs
// no login and returns nil when they are satisfied. Otherwise the request is
// sent to the login page once; after that login, or under prompt=none, it
// returns unmet_authentication_requirements.
func (g *AuthorizeInteractionResponseGenerator) handleRequestedAcr(req *validators_models.ValidatedAuthorizeRequest) *responses_models.InteractionResponse {
	if !g.requestedAcrRequired || requestedAcrSatisfied(req) {
		return nil
	}
	if promptNone(req) || slices.Contains(req.SuppressedPromptModes, wicket.PromptModesLogin) {
		return &responses_models.InteractionResponse{
			Error:            wicket.AuthorizeErrorsUnmetAuthenticationRequirements,
			ErrorDescription: unmetRequestedAcrDescription,
		}
	}
	markRequestedAcrLogin(req)
	return &responses_models.InteractionResponse{IsLogin: true}
}
