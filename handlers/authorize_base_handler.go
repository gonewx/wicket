// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"log/slog"
	"net/http"
	"net/url"

	"github.com/gonewx/wicket/handlers/results"
	"github.com/gonewx/wicket/models/messages"
	"github.com/gonewx/wicket/responses"
	responses_models "github.com/gonewx/wicket/responses/models"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/validators"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// endpointResult is the write-out contract shared by every handler result. A
// handler selects one result and lets it render the HTTP response, so a protocol
// error reaches the client through the result rather than as a Process error.
type endpointResult interface {
	Execute(w http.ResponseWriter, r *http.Request) error
}

// authorizeBaseHandler carries the shared authorize pipeline: it validates the
// gathered parameters against the current subject, asks the interaction stage
// what the request still needs, and turns that decision into a single result.
// Both the front-channel authorize entry and the post-interaction callback
// compose it.
type authorizeBaseHandler struct {
	validator   validators.AuthorizeRequestValidator
	interaction responses.AuthorizeInteractionResponseGenerator
	generator   responses.AuthorizeResponseGenerator
	session     services.UserSession
	logger      *slog.Logger
}

// validate runs protocol validation of the request parameters against the
// current subject.
func (h *authorizeBaseHandler) validate(values url.Values) *validators_models.AuthorizeRequestValidationResult {
	return h.validator.Validate(values, h.session.GetUser())
}

// dispatch maps a validated request plus any consent answer onto the result that
// expresses the request's next step. Error paths (validation or interaction)
// take precedence over interaction redirects, which take precedence over issuing
// the final authorization response.
func (h *authorizeBaseHandler) dispatch(validation *validators_models.AuthorizeRequestValidationResult, consent *messages.ConsentResponse) (endpointResult, error) {
	if validation.Error != nil {
		return h.errorResult(validation.ValidatedRequest, validation.Error, validation.Description), nil
	}

	request := validation.ValidatedRequest
	interaction := h.interaction.Handle(request, consent)
	switch {
	case interaction.IsError():
		return h.errorResult(request, interaction.Error, interaction.ErrorDescription), nil
	case interaction.IsLogin:
		return results.NewLoginPageResult(request), nil
	case interaction.IsConsent:
		return results.NewConsentPageResult(request), nil
	case interaction.IsRedirect():
		return results.NewCustomRedirectResult(request, interaction.RedirectUrl), nil
	}

	response, err := h.generator.Create(request)
	if err != nil {
		// A generator failure is surfaced to the client through the authorize
		// result: safe errors return to the client, everything else renders the
		// error page. This keeps a failed response from being reported as 501.
		return h.errorResult(request, err, ""), nil
	}
	return results.NewAuthorizeResult(response), nil
}

// errorResult wraps a protocol error in an authorize result. For an OpenID
// request tied to a session it also derives the session_state so the client can
// still observe session changes on the error response.
func (h *authorizeBaseHandler) errorResult(request *validators_models.ValidatedAuthorizeRequest, err error, description string) *results.AuthorizeResult {
	response := responses_models.NewAuthorizeResponse()
	response.Request = request
	response.Error = err
	response.ErrorDescription = description
	if request != nil {
		response.SessionState = request.GenerateSessionStateValue()
	}
	return results.NewAuthorizeResult(response)
}
