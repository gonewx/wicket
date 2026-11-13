// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/claims"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/extensions"
	"github.com/gonewx/wicket/handlers/results"
	"github.com/gonewx/wicket/models/messages"
	"github.com/gonewx/wicket/responses"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/validators"
)

// AuthorizeCallbackHandler resumes an authorize request after the user returns
// from an interactive login or consent page. It recovers the original
// parameters, replays them through the shared pipeline together with any stored
// consent answer, and consumes that answer once it has been applied.
//
// A handler that holds options enforces Endpoints.EnableAuthorizeEndpoint, the
// switch it shares with the authorize endpoint: while the switch is off it
// answers 404 to every request and leaves any stored consent answer untouched.
// A handler without options does not look at the switch and always serves.
type AuthorizeCallbackHandler struct {
	base       authorizeBaseHandler
	consent    storage.ConsentMessageStore
	parameters storage.AuthorizationParametersMessageStore
	options    *config_options.WicketOptions
}

// NewAuthorizeCallbackHandler builds an authorize callback handler that holds
// no options. It does not enforce Endpoints.EnableAuthorizeEndpoint and serves
// whatever the switch says; use NewAuthorizeCallbackHandlerWithOptions for a
// handler that honors the switch.
func NewAuthorizeCallbackHandler(
	validator validators.AuthorizeRequestValidator,
	interaction responses.AuthorizeInteractionResponseGenerator,
	generator responses.AuthorizeResponseGenerator,
	session services.UserSession,
	consent storage.ConsentMessageStore,
	parameters storage.AuthorizationParametersMessageStore,
	logger *slog.Logger,
) *AuthorizeCallbackHandler {
	return NewAuthorizeCallbackHandlerWithOptions(validator, interaction, generator, session, consent, parameters, nil, logger)
}

// NewAuthorizeCallbackHandlerWithOptions builds an authorize callback handler
// that holds options and enforces Endpoints.EnableAuthorizeEndpoint: while the
// switch is off the handler answers 404 to every request. The switch is read on
// each request. Nil options leave the endpoint on.
func NewAuthorizeCallbackHandlerWithOptions(
	validator validators.AuthorizeRequestValidator,
	interaction responses.AuthorizeInteractionResponseGenerator,
	generator responses.AuthorizeResponseGenerator,
	session services.UserSession,
	consent storage.ConsentMessageStore,
	parameters storage.AuthorizationParametersMessageStore,
	options *config_options.WicketOptions,
	logger *slog.Logger,
) *AuthorizeCallbackHandler {
	return &AuthorizeCallbackHandler{
		base: authorizeBaseHandler{
			validator:   validator,
			interaction: interaction,
			generator:   generator,
			session:     session,
			logger:      logger,
		},
		consent:    consent,
		parameters: parameters,
		options:    options,
	}
}

func (h *AuthorizeCallbackHandler) Process(w http.ResponseWriter, r *http.Request) error {
	// A switched-off endpoint answers as if it did not exist, whatever the
	// request looks like, and before anything of the request is read.
	if h.options != nil && !h.options.Endpoints.EnableAuthorizeEndpoint {
		return results.NewStatusCodeResult(http.StatusNotFound).Execute(w, r)
	}
	if r.Method != http.MethodGet {
		return results.NewStatusCodeResult(http.StatusMethodNotAllowed).Execute(w, r)
	}
	result, err := h.result(r)
	if err != nil {
		return err
	}
	return result.Execute(w, r)
}

// result recovers the original parameters, loads any consent answer for the
// current subject, and replays the shared pipeline. A consumed answer is deleted
// so a replayed callback cannot reuse it.
func (h *AuthorizeCallbackHandler) result(r *http.Request) (endpointResult, error) {
	values := h.recoverParameters(r)
	key := consentRequestKey(h.base.session.GetUser(), values)

	message, err := h.consent.Read(r.Context(), key)
	if err != nil {
		return nil, fmt.Errorf("read consent message: %w", err)
	}

	validation := h.base.validate(r.Context(), values)

	if message != nil && message.Data == nil {
		// The consent message exists but carries no answer: the callback cannot
		// complete, so it fails to the error page and the empty message is
		// discarded.
		_ = h.consent.Delete(r.Context(), key)
		return h.base.errorResult(validation.ValidatedRequest, wicket.AuthorizeErrorsInvalidRequest, ""), nil
	}

	var answer *messages.ConsentResponse
	if message != nil {
		answer = message.Data
	}

	result, err := h.base.dispatch(r.Context(), validation, answer)
	if err != nil {
		return nil, err
	}
	if message != nil {
		// The consent answer is one-time; once applied it is removed.
		_ = h.consent.Delete(r.Context(), key)
	}
	return result, nil
}

// recoverParameters restores the original authorize parameters. When an
// authorization-parameters store is configured the callback carries a stored
// handle; otherwise the parameters travel inline on the callback query string.
// A callback that carries no handle keeps its inline parameters even when a
// store is configured — reading an empty handle could otherwise yield an
// empty-but-valid message that silently blanks the real parameters.
func (h *AuthorizeCallbackHandler) recoverParameters(r *http.Request) url.Values {
	values := r.URL.Query()
	if h.parameters != nil {
		if storeId := values.Get(wicket.AuthorizationParamsStoreMessageStoreIdParameterName); storeId != "" {
			if message, err := h.parameters.Read(r.Context(), storeId); err == nil && message != nil && message.Data != nil {
				values = message.Data
			}
		}
	}
	return values
}

// consentRequestKey derives the stable storage key for a subject's consent
// answer from the subject identifier and the request parameters, so the page
// that records the answer and the callback that consumes it agree on the key.
func consentRequestKey(subject *claims.ClaimsPrincipal, values url.Values) string {
	subjectId := ""
	if subject != nil {
		subjectId = extensions.GetSubjectIdFromPrincipal(subject)
	}
	sum := sha256.Sum256([]byte(subjectId + "|" + values.Encode()))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
