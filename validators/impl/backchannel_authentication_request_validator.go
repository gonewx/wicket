// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
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

func (v *BackchannelAuthenticationRequestValidator) Validate(values url.Values, client *storage_models.Client) *validators_models.BackchannelAuthenticationRequestValidationResult {
	if client == nil {
		return validators_models.NewBackchannelAuthenticationRequestValidationError(gois.TokenErrorsInvalidClient, "")
	}
	if !utils.Contains(client.AllowedGrantTypes(), gois.GrantTypeBackchannelAuthentication) {
		return validators_models.NewBackchannelAuthenticationRequestValidationError(gois.TokenErrorsUnauthorizedClient, "")
	}
	mode := client.BackchannelTokenDeliveryMode
	if mode == "" {
		mode = gois.BackchannelTokenDeliveryModesPoll
	}
	if !utils.Contains(v.options.BackchannelAuthentication.AllowedDeliveryModes, mode) {
		return validators_models.NewBackchannelAuthenticationRequestValidationError(gois.TokenErrorsInvalidRequest, "")
	}
	if values.Get(gois.BackchannelAuthenticationRequestRequest) != "" && len(values.Get(gois.BackchannelAuthenticationRequestRequest)) > v.options.InputLengthRestrictions.Jwt {
		return validators_models.NewBackchannelAuthenticationRequestValidationError(gois.TokenErrorsInvalidRequest, "")
	}
	scope := values.Get(gois.BackchannelAuthenticationRequestScope)
	if scope == "" {
		return validators_models.NewBackchannelAuthenticationRequestValidationError(gois.TokenErrorsInvalidScope, "")
	}
	if len(scope) > v.options.InputLengthRestrictions.Scope {
		return validators_models.NewBackchannelAuthenticationRequestValidationError(gois.TokenErrorsInvalidScope, "")
	}
	scopes := utils.ParseScopesString(scope)
	resources := values[gois.BackchannelAuthenticationRequestResource]
	if utils.AnyPred(resources, func(x string) bool { return len(x) > v.options.InputLengthRestrictions.ResourceGapMaxLength }) {
		return validators_models.NewBackchannelAuthenticationRequestValidationError(gois.TokenErrorsInvalidTarget, "")
	}
	validation, err := v.resources.ValidateRequestedResources(&validators_models.ResourceValidationRequest{
		Client:       client,
		Scopes:       scopes,
		ResourceGaps: resources,
	})
	if err != nil {
		return validators_models.NewBackchannelAuthenticationRequestValidationError(err, "")
	}
	if !validation.Succeeded() {
		if len(validation.InvalidResourceGaps) > 0 {
			return validators_models.NewBackchannelAuthenticationRequestValidationError(gois.TokenErrorsInvalidTarget, "")
		}
		return validators_models.NewBackchannelAuthenticationRequestValidationError(gois.TokenErrorsInvalidScope, "")
	}
	userCtx := &validators_models.BackchannelAuthenticationUserValidationContext{
		LoginHint:      values.Get(gois.BackchannelAuthenticationRequestLoginHint),
		IdTokenHint:    values.Get(gois.BackchannelAuthenticationRequestIdTokenHint),
		LoginHintToken: values.Get(gois.BackchannelAuthenticationRequestLoginHintToken),
		Client:         client,
	}
	if tooLong(userCtx.LoginHint, v.options.InputLengthRestrictions.LoginHint) ||
		tooLong(userCtx.IdTokenHint, v.options.InputLengthRestrictions.IdTokenHint) ||
		tooLong(userCtx.LoginHintToken, v.options.InputLengthRestrictions.LoginHintToken) {
		return validators_models.NewBackchannelAuthenticationRequestValidationError(gois.TokenErrorsInvalidRequest, "")
	}
	if err := v.users.Validate(userCtx); err != nil {
		return validators_models.NewBackchannelAuthenticationRequestValidationError(gois.TokenErrorsInvalidRequest, "")
	}
	if tooLong(values.Get(gois.BackchannelAuthenticationRequestBindingMessage), v.options.InputLengthRestrictions.BindingMessage) ||
		tooLong(values.Get(gois.BackchannelAuthenticationRequestUserCode), v.options.InputLengthRestrictions.UserCode) {
		return validators_models.NewBackchannelAuthenticationRequestValidationError(gois.TokenErrorsInvalidRequest, "")
	}
	lifetime := v.options.BackchannelAuthentication.DefaultRequestLifetime
	if client.BackchannelAuthenticationLifetime != nil && *client.BackchannelAuthenticationLifetime > 0 {
		lifetime = *client.BackchannelAuthenticationLifetime
	}
	if raw := strings.TrimSpace(values.Get(gois.BackchannelAuthenticationRequestRequestedExpiry)); raw != "" {
		requested, err := strconv.Atoi(raw)
		if err != nil || requested <= 0 {
			return validators_models.NewBackchannelAuthenticationRequestValidationError(gois.TokenErrorsInvalidRequest, "")
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
		BindingMessage:             values.Get(gois.BackchannelAuthenticationRequestBindingMessage),
		UserCode:                   values.Get(gois.BackchannelAuthenticationRequestUserCode),
		RequestObject:              values.Get(gois.BackchannelAuthenticationRequestRequest),
		Status:                     storage_models.BackchannelAuthenticationRequestStatusPending,
		CreationTime:               now,
		ExpirationTime:             now.Add(time.Duration(lifetime) * time.Second),
		PollInterval:               interval,
		ClientNotificationToken:    values.Get(gois.BackchannelAuthenticationRequestClientNotificationToken),
		ClientNotificationEndpoint: client.ClientNotificationEndpoint,
	}
	if err := v.store.StoreBackchannelAuthenticationRequest(requestID, request); err != nil {
		return validators_models.NewBackchannelAuthenticationRequestValidationError(err, "")
	}
	if mode == gois.BackchannelTokenDeliveryModesPing {
		if err := v.notifications.Notify(request); err != nil {
			return validators_models.NewBackchannelAuthenticationRequestValidationError(gois.TokenErrorsInvalidRequest, "")
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
