// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/gonewx/wicket"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/extensions"
	"github.com/gonewx/wicket/handlers/results"
	"github.com/gonewx/wicket/responses"
	"github.com/gonewx/wicket/validators"
)

// basicChallenge is the challenge written when the client authenticated with
// the Basic scheme or with an Authorization header whose scheme cannot be
// read. RFC 7617 §2 makes the realm parameter mandatory for Basic.
const basicChallenge = `Basic realm="wicket"`

// TokenRevocationHandler serves RFC 7009 token revocation for authenticated
// clients. It revokes refresh tokens and reference access tokens; a JWT
// access token carries no server-side state and is refused.
type TokenRevocationHandler struct {
	clientValidator  validators.ClientSecretValidator
	requestValidator validators.TokenRevocationRequestValidator
	generator        responses.TokenRevocationResponseGenerator
	options          *config_options.WicketOptions
	logger           *slog.Logger
}

func NewTokenRevocationHandler(
	clientValidator validators.ClientSecretValidator,
	requestValidator validators.TokenRevocationRequestValidator,
	generator responses.TokenRevocationResponseGenerator,
	options *config_options.WicketOptions,
	logger *slog.Logger,
) *TokenRevocationHandler {
	return &TokenRevocationHandler{
		clientValidator:  clientValidator,
		requestValidator: requestValidator,
		generator:        generator,
		options:          options,
		logger:           logger,
	}
}

func (h *TokenRevocationHandler) Process(w http.ResponseWriter, r *http.Request) error {
	// A switched-off endpoint answers as if it did not exist, whatever the
	// request looks like, and before anything of the request is read.
	if !h.options.Endpoints.EnableTokenRevocationEndpoint {
		return results.NewStatusCodeResult(http.StatusNotFound).Execute(w, r)
	}
	if r.Method != http.MethodPost {
		return results.NewStatusCodeResult(http.StatusMethodNotAllowed).Execute(w, r)
	}
	if !extensions.HasApplicationFormContentType(r) {
		return results.NewStatusCodeResult(http.StatusUnsupportedMediaType).Execute(w, r)
	}
	if err := r.ParseForm(); err != nil {
		return results.NewTokenRevocationErrorResult(wicket.TokenErrorsInvalidRequest).Execute(w, r)
	}

	clientResult := h.clientValidator.Validate(r)
	if clientResult == nil || clientResult.Error != nil || clientResult.Client == nil {
		h.debug("revocation client authentication failed")
		challenge := authorizationChallenge(r)
		return results.NewClientAuthenticationErrorResult(challenge).Execute(w, r)
	}

	// RFC 7009 §2.1 carries the parameters in the request body; the query
	// string is never consulted.
	if len(r.PostForm) == 0 {
		return results.NewTokenRevocationErrorResult(wicket.TokenErrorsInvalidRequest).Execute(w, r)
	}

	validation, err := h.requestValidator.ValidateRequest(r.Context(), r.PostForm, clientResult.Client)
	if err != nil {
		return fmt.Errorf("validate revocation request: %w", err)
	}
	if validation.Error != nil {
		return results.NewTokenRevocationErrorResult(validation.Error).Execute(w, r)
	}

	// A JWT access token cannot be revoked here, so it is refused rather than
	// answered with a 200 that would promise it is no longer usable (RFC 7009
	// §2.2.1). The test for the JWT form is the same one access token
	// validation uses to tell a JWT from a reference handle; see
	// ValidateAccessToken in validators/impl/token_validator.go. It looks at
	// the form only: the token is not parsed and the hint plays no part, so
	// the answer does not depend on whose token it is or whether it is valid.
	if strings.Contains(validation.Token, ".") {
		h.debug("revocation request rejected",
			slog.String("clientId", clientResult.Client.ClientId),
			slog.String("tokenTypeHint", validation.TokenTypeHint),
			slog.String("error", wicket.RevocationErrorsUnsupportedTokenType.Error()),
		)
		return results.NewTokenRevocationErrorResult(wicket.RevocationErrorsUnsupportedTokenType).Execute(w, r)
	}

	response, err := h.generator.Handle(r.Context(), validation)
	if err != nil {
		return fmt.Errorf("revoke token: %w", err)
	}

	// RFC 7009 §2.2: the answer is 200 whether or not the token was found,
	// so the generator's result only feeds the log.
	h.debug("revocation request processed",
		slog.String("clientId", clientResult.Client.ClientId),
		slog.String("tokenTypeHint", validation.TokenTypeHint),
		slog.Bool("found", response != nil && response.Success),
	)

	results.HttpRespSetNoCache(w)
	w.WriteHeader(http.StatusOK)
	return nil
}

func (h *TokenRevocationHandler) debug(msg string, args ...any) {
	if h.logger != nil {
		h.logger.Debug(msg, args...)
	}
}

// authorizationChallenge returns the WWW-Authenticate challenge answering the
// request's Authorization header: the header's scheme name, or the Basic
// challenge for Basic and for a scheme that cannot be read. It returns "" when
// the request carries no Authorization header.
func authorizationChallenge(r *http.Request) string {
	values, present := r.Header["Authorization"]
	if !present {
		return ""
	}

	scheme := ""
	if len(values) > 0 {
		if fields := strings.Fields(values[0]); len(fields) > 0 {
			scheme = fields[0]
		}
	}
	if scheme == "" || !isHttpToken(scheme) || strings.EqualFold(scheme, "Basic") {
		return basicChallenge
	}
	return scheme
}

// isHttpToken reports whether s is an RFC 9110 §5.6.2 token, the form an
// authentication scheme name takes.
func isHttpToken(s string) bool {
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.ContainsRune("!#$%&'*+-.^_`|~", c):
		default:
			return false
		}
	}
	return s != ""
}
