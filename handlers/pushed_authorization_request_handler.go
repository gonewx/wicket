// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/clientassertion"
	"github.com/gonewx/wicket/extensions"
	"github.com/gonewx/wicket/handlers/results"
	"github.com/gonewx/wicket/pushedauth"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/validators"
)

// PushedAuthorizationPusher stores the parameters of a pushed authorization
// request. pushedauth.Service implements it.
type PushedAuthorizationPusher interface {
	// Push stores parameters for client and returns the request_uri and its
	// lifetime in seconds.
	Push(ctx context.Context, client *storage_models.Client, parameters url.Values) (string, int, error)
}

var _ PushedAuthorizationPusher = (*pushedauth.Service)(nil)

// pushedClientAuthenticationParameters authenticate the push; they are
// removed before the parameters are validated and stored.
var pushedClientAuthenticationParameters = []string{
	"client_secret",
	"client_assertion",
	"client_assertion_type",
}

// pushedAuthorizationServerErrorBody is the whole body of a push that failed
// for an infrastructure reason.
const pushedAuthorizationServerErrorBody = "Internal Server Error\n"

// PushedAuthorizationRequestHandler serves the pushed authorization request
// endpoint of RFC 9126: an authenticated client posts the parameters of an
// authorization request and receives the request_uri that stands for them.
// It is only routed while pushed authorization requests are enabled.
type PushedAuthorizationRequestHandler struct {
	clientValidator  validators.ClientSecretValidator
	requestValidator validators.AuthorizeRequestValidator
	pusher           PushedAuthorizationPusher
	logger           *slog.Logger
}

// NewPushedAuthorizationRequestHandler builds the handler. clientValidator is
// the client authenticator every authenticated endpoint uses.
func NewPushedAuthorizationRequestHandler(
	clientValidator validators.ClientSecretValidator,
	requestValidator validators.AuthorizeRequestValidator,
	pusher PushedAuthorizationPusher,
	logger *slog.Logger,
) *PushedAuthorizationRequestHandler {
	return &PushedAuthorizationRequestHandler{
		clientValidator:  clientValidator,
		requestValidator: requestValidator,
		pusher:           pusher,
		logger:           logger,
	}
}

func (h *PushedAuthorizationRequestHandler) Process(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodPost {
		return results.NewStatusCodeResult(http.StatusMethodNotAllowed).Execute(w, r)
	}
	if !extensions.HasApplicationFormContentType(r) {
		return results.NewStatusCodeResult(http.StatusUnsupportedMediaType).Execute(w, r)
	}
	if err := r.ParseForm(); err != nil {
		return writePushedAuthorizationError(w, wicket.AuthorizeErrorsInvalidRequest, "")
	}

	clientResult := h.clientValidator.Validate(r)
	if clientResult != nil && errors.Is(clientResult.Error, clientassertion.ErrAuthenticationUnavailable) {
		writeClientAuthenticationUnavailable(w)
		return nil
	}
	if clientResult == nil || clientResult.Error != nil || clientResult.Client == nil {
		h.debug("pushed authorization client authentication failed")
		return results.NewClientAuthenticationErrorResult(authorizationChallenge(r)).Execute(w, r)
	}
	client := clientResult.Client

	// RFC 9126 section 2.1 carries the parameters in the request body; the
	// query string is never consulted.
	parameters := make(url.Values, len(r.PostForm))
	for key, list := range r.PostForm {
		parameters[key] = slices.Clone(list)
	}
	if ids, present := parameters[wicket.AuthorizeRequestClientId]; present {
		if len(ids) != 1 || ids[0] != client.ClientId {
			return writePushedAuthorizationError(w, wicket.AuthorizeErrorsInvalidRequest, "client_id does not match the authenticated client")
		}
	} else {
		parameters.Set(wicket.AuthorizeRequestClientId, client.ClientId)
	}
	for _, name := range pushedClientAuthenticationParameters {
		delete(parameters, name)
	}

	working := make(url.Values, len(parameters))
	for key, list := range parameters {
		working[key] = slices.Clone(list)
	}
	validation := h.requestValidator.Validate(r.Context(), working, nil, validators.AuthorizeRequestPhasePush)
	if validation == nil {
		writePushedAuthorizationServerError(w)
		return nil
	}
	if validation.Error != nil {
		if errors.Is(validation.Error, wicket.AuthorizeErrorsServerError) {
			writePushedAuthorizationServerError(w)
			return nil
		}
		h.debug("pushed authorization request rejected", slog.String("clientId", client.ClientId), slog.String("error", validation.Error.Error()))
		return writePushedAuthorizationError(w, validation.Error, validation.Description)
	}

	requestURI, expiresIn, err := h.pusher.Push(r.Context(), client, parameters)
	if err != nil {
		if h.logger != nil {
			h.logger.Error("pushed authorization request could not be stored", slog.String("clientId", client.ClientId), slog.String("error", err.Error()))
		}
		writePushedAuthorizationServerError(w)
		return nil
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusCreated)
	return json.NewEncoder(w).Encode(struct {
		RequestUri string `json:"request_uri"`
		ExpiresIn  int    `json:"expires_in"`
	}{RequestUri: requestURI, ExpiresIn: expiresIn})
}

func (h *PushedAuthorizationRequestHandler) debug(msg string, args ...any) {
	if h.logger != nil {
		h.logger.Debug(msg, args...)
	}
}

// writePushedAuthorizationError writes the 400 error response of RFC 9126
// section 2.3.
func writePushedAuthorizationError(w http.ResponseWriter, protocolError error, description string) error {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusBadRequest)
	body := map[string]string{"error": protocolError.Error()}
	if description != "" {
		body["error_description"] = description
	}
	return json.NewEncoder(w).Encode(body)
}

// writePushedAuthorizationServerError answers a push that failed for an
// infrastructure reason, without any detail of the failure.
func writePushedAuthorizationServerError(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = w.Write([]byte(pushedAuthorizationServerErrorBody))
}
