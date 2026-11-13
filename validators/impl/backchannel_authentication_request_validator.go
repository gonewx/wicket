// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gonewx/wicket"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/storage"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/utils"
	"github.com/gonewx/wicket/validators"
	validators_models "github.com/gonewx/wicket/validators/models"
)

type BackchannelAuthenticationRequestValidator struct {
	options       *config_options.WicketOptions
	store         storage.BackchannelAuthenticationRequestStore
	resources     validators.ResourceValidator
	users         validators.BackchannelAuthenticationUserValidator
	notifications services.BackchannelAuthenticationNotificationService
	clock         services.SystemClock
	logger        *slog.Logger
}

func NewBackchannelAuthenticationRequestValidator(
	options *config_options.WicketOptions,
	store storage.BackchannelAuthenticationRequestStore,
	resources validators.ResourceValidator,
	users validators.BackchannelAuthenticationUserValidator,
	notifications services.BackchannelAuthenticationNotificationService,
	clock services.SystemClock,
	logger *slog.Logger,
) *BackchannelAuthenticationRequestValidator {
	return &BackchannelAuthenticationRequestValidator{
		options:       options,
		store:         store,
		resources:     resources,
		users:         users,
		notifications: notifications,
		clock:         clock,
		logger:        logger,
	}
}

func (v *BackchannelAuthenticationRequestValidator) Validate(ctx context.Context, values url.Values, client *storage_models.Client) *validators_models.BackchannelAuthenticationRequestValidationResult {
	if client == nil {
		return validators_models.NewBackchannelAuthenticationRequestValidationError(wicket.TokenErrorsInvalidClient, "")
	}
	if !utils.Contains(client.AllowedGrantTypes(), wicket.GrantTypeBackchannelAuthentication) {
		return validators_models.NewBackchannelAuthenticationRequestValidationError(wicket.TokenErrorsUnauthorizedClient, "")
	}
	mode := client.BackchannelTokenDeliveryMode
	if mode == "" {
		mode = wicket.BackchannelTokenDeliveryModesPoll
	}
	if !utils.Contains(v.options.BackchannelAuthentication.AllowedDeliveryModes, mode) {
		return validators_models.NewBackchannelAuthenticationRequestValidationError(wicket.TokenErrorsInvalidRequest, "")
	}
	if values.Get(wicket.BackchannelAuthenticationRequestRequest) != "" && len(values.Get(wicket.BackchannelAuthenticationRequestRequest)) > v.options.InputLengthRestrictions.Jwt {
		return validators_models.NewBackchannelAuthenticationRequestValidationError(wicket.TokenErrorsInvalidRequest, "")
	}
	scope := values.Get(wicket.BackchannelAuthenticationRequestScope)
	if scope == "" {
		return validators_models.NewBackchannelAuthenticationRequestValidationError(wicket.TokenErrorsInvalidScope, "")
	}
	if len(scope) > v.options.InputLengthRestrictions.Scope {
		return validators_models.NewBackchannelAuthenticationRequestValidationError(wicket.TokenErrorsInvalidScope, "")
	}
	scopes := utils.ParseScopesString(scope)
	resources := values[wicket.BackchannelAuthenticationRequestResource]
	if utils.AnyPred(resources, func(x string) bool { return len(x) > v.options.InputLengthRestrictions.ResourceGapMaxLength }) {
		return validators_models.NewBackchannelAuthenticationRequestValidationError(wicket.TokenErrorsInvalidTarget, "")
	}
	validation, err := v.resources.ValidateRequestedResources(ctx, &validators_models.ResourceValidationRequest{
		Client:       client,
		Scopes:       scopes,
		ResourceGaps: resources,
	})
	if err != nil {
		return validators_models.NewBackchannelAuthenticationRequestValidationError(err, "")
	}
	if !validation.Succeeded() {
		if len(validation.InvalidResourceGaps) > 0 {
			return validators_models.NewBackchannelAuthenticationRequestValidationError(wicket.TokenErrorsInvalidTarget, "")
		}
		return validators_models.NewBackchannelAuthenticationRequestValidationError(wicket.TokenErrorsInvalidScope, "")
	}
	userCtx := &validators_models.BackchannelAuthenticationUserValidationContext{
		LoginHint:      values.Get(wicket.BackchannelAuthenticationRequestLoginHint),
		IdTokenHint:    values.Get(wicket.BackchannelAuthenticationRequestIdTokenHint),
		LoginHintToken: values.Get(wicket.BackchannelAuthenticationRequestLoginHintToken),
		Client:         client,
	}
	if tooLong(userCtx.LoginHint, v.options.InputLengthRestrictions.LoginHint) ||
		tooLong(userCtx.IdTokenHint, v.options.InputLengthRestrictions.IdTokenHint) ||
		tooLong(userCtx.LoginHintToken, v.options.InputLengthRestrictions.LoginHintToken) {
		return validators_models.NewBackchannelAuthenticationRequestValidationError(wicket.TokenErrorsInvalidRequest, "")
	}
	if err := v.users.Validate(ctx, userCtx); err != nil {
		return validators_models.NewBackchannelAuthenticationRequestValidationError(wicket.TokenErrorsInvalidRequest, "")
	}
	if tooLong(values.Get(wicket.BackchannelAuthenticationRequestBindingMessage), v.options.InputLengthRestrictions.BindingMessage) ||
		tooLong(values.Get(wicket.BackchannelAuthenticationRequestUserCode), v.options.InputLengthRestrictions.UserCode) {
		return validators_models.NewBackchannelAuthenticationRequestValidationError(wicket.TokenErrorsInvalidRequest, "")
	}
	lifetime := v.options.BackchannelAuthentication.DefaultRequestLifetime
	if client.BackchannelAuthenticationLifetime != nil && *client.BackchannelAuthenticationLifetime > 0 {
		lifetime = *client.BackchannelAuthenticationLifetime
	}
	if raw := strings.TrimSpace(values.Get(wicket.BackchannelAuthenticationRequestRequestedExpiry)); raw != "" {
		requested, err := strconv.Atoi(raw)
		if err != nil || requested <= 0 {
			return validators_models.NewBackchannelAuthenticationRequestValidationError(wicket.TokenErrorsInvalidRequest, "")
		}
		if requested < lifetime {
			lifetime = requested
		}
	}
	interval := v.options.BackchannelAuthentication.DefaultPollingInterval
	if client.PollingInterval != nil && *client.PollingInterval > 0 {
		interval = *client.PollingInterval
	}
	requestID, err := newAuthenticationRequestID()
	if err != nil {
		return validators_models.NewBackchannelAuthenticationRequestValidationError(err, "")
	}
	now := v.clock.Now()
	request := &storage_models.BackchannelAuthenticationRequest{
		RequestId:                  requestID,
		ClientId:                   client.ClientId,
		SubjectId:                  userCtx.LoginHint,
		Subject:                    userCtx.Subject,
		RequestedScopes:            scopes,
		RequestedResourceGaps:      resources,
		DeliveryMode:               mode,
		BindingMessage:             values.Get(wicket.BackchannelAuthenticationRequestBindingMessage),
		UserCode:                   values.Get(wicket.BackchannelAuthenticationRequestUserCode),
		RequestObject:              values.Get(wicket.BackchannelAuthenticationRequestRequest),
		Status:                     storage_models.BackchannelAuthenticationRequestStatusPending,
		CreationTime:               now,
		ExpirationTime:             now.Add(time.Duration(lifetime) * time.Second),
		PollInterval:               interval,
		ClientNotificationToken:    values.Get(wicket.BackchannelAuthenticationRequestClientNotificationToken),
		ClientNotificationEndpoint: client.ClientNotificationEndpoint,
	}
	if err := v.store.StoreBackchannelAuthenticationRequest(ctx, requestID, request); err != nil {
		return validators_models.NewBackchannelAuthenticationRequestValidationError(err, "")
	}
	if mode == wicket.BackchannelTokenDeliveryModesPing {
		if err := v.notifications.Notify(request); err != nil {
			return validators_models.NewBackchannelAuthenticationRequestValidationError(wicket.TokenErrorsInvalidRequest, "")
		}
	}
	result := validators_models.NewBackchannelAuthenticationRequestValidationResult()
	result.Request = request
	result.ExpiresIn = lifetime
	result.Interval = interval
	return result
}

func tooLong(value string, max int) bool {
	return max > 0 && len(value) > max
}

func newAuthenticationRequestID() (string, error) {
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
