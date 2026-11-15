// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"log/slog"
	"mime"
	"net/http"
	"net/url"

	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/handlers/results"
	"github.com/gonewx/wicket/responses"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/validators"
)

const formUrlEncodedMediaType = "application/x-www-form-urlencoded"

// AuthorizeHandler serves the front-channel authorize endpoint. It accepts GET
// query parameters or a urlencoded form POST, replays them through the shared
// authorize pipeline with no prior consent, and writes the resulting response.
//
// A handler that holds options enforces Endpoints.EnableAuthorizeEndpoint:
// while the switch is off it answers 404 to every request. A handler without
// options does not look at the switch and always serves.
type AuthorizeHandler struct {
	base    authorizeBaseHandler
	options *config_options.WicketOptions
}

// NewAuthorizeHandler builds an authorize handler that holds no options. It
// does not enforce Endpoints.EnableAuthorizeEndpoint and serves whatever the
// switch says; use NewAuthorizeHandlerWithOptions for a handler that honors the
// switch.
func NewAuthorizeHandler(
	validator validators.AuthorizeRequestValidator,
	interaction responses.AuthorizeInteractionResponseGenerator,
	generator responses.AuthorizeResponseGenerator,
	session services.UserSession,
	logger *slog.Logger,
) *AuthorizeHandler {
	return NewAuthorizeHandlerWithOptions(validator, interaction, generator, session, nil, logger)
}

// NewAuthorizeHandlerWithOptions builds an authorize handler that holds options
// and enforces Endpoints.EnableAuthorizeEndpoint: while the switch is off the
// handler answers 404 to every request. The switch is read on each request. Nil
// options leave the endpoint on.
func NewAuthorizeHandlerWithOptions(
	validator validators.AuthorizeRequestValidator,
	interaction responses.AuthorizeInteractionResponseGenerator,
	generator responses.AuthorizeResponseGenerator,
	session services.UserSession,
	options *config_options.WicketOptions,
	logger *slog.Logger,
) *AuthorizeHandler {
	return &AuthorizeHandler{
		base: authorizeBaseHandler{
			validator:   validator,
			interaction: interaction,
			generator:   generator,
			session:     session,
			logger:      logger,
		},
		options: options,
	}
}

// SetPushedAuthorizationConsumer installs the consumer of pushed
// authorization requests of an assembly with pushed authorization enabled.
func (h *AuthorizeHandler) SetPushedAuthorizationConsumer(consumer PushedAuthorizationConsumer) {
	h.base.pushed = consumer
}

func (h *AuthorizeHandler) Process(w http.ResponseWriter, r *http.Request) error {
	// A switched-off endpoint answers as if it did not exist, whatever the
	// request looks like, and before anything of the request is read.
	if h.options != nil && !h.options.Endpoints.EnableAuthorizeEndpoint {
		return results.NewStatusCodeResult(http.StatusNotFound).Execute(w, r)
	}
	result, err := h.result(r)
	if err != nil {
		return err
	}
	return result.Execute(w, r)
}

// result gathers the request parameters and defers to the shared pipeline. A
// POST that is not a urlencoded form is rejected at the content-type gate.
func (h *AuthorizeHandler) result(r *http.Request) (endpointResult, error) {
	values, ok := gatherAuthorizeParameters(r)
	if !ok {
		return results.NewStatusCodeResult(http.StatusUnsupportedMediaType), nil
	}
	return h.base.dispatch(r.Context(), h.base.validate(r.Context(), values, validators.AuthorizeRequestPhaseEntry), nil)
}

// gatherAuthorizeParameters reads parameters from the query string for GET and
// from the urlencoded body otherwise. The boolean is false when a non-GET
// request does not carry a urlencoded form body.
func gatherAuthorizeParameters(r *http.Request) (url.Values, bool) {
	if r.Method == http.MethodGet {
		return r.URL.Query(), true
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != formUrlEncodedMediaType {
		return nil, false
	}
	if err := r.ParseForm(); err != nil {
		return nil, false
	}
	return r.PostForm, true
}
