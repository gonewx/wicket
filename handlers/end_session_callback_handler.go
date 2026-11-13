// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/gonewx/wicket"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/handlers/results"
	"github.com/gonewx/wicket/models/contexts"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/validators"
)

// endSessionNotificationMaxAge bounds how long after the logout context was
// published a callback load still triggers back-channel logout delivery, so a
// replayed callback address stops notifying relying parties.
const endSessionNotificationMaxAge = 300 * time.Second

// EndSessionCallbackHandler renders the front-channel logout iframes after
// logout and, from the same logout context, triggers back-channel logout
// delivery to the relying parties that registered for it.
type EndSessionCallbackHandler struct {
	requestValidator  validators.EndSessionRequestValidator
	backChannelLogout services.BackchannelLogoutService
	notifications     storage.MessageStore[contexts.LogoutNotificationContext]
	clock             services.SystemClock
	options           *config_options.WicketOptions
	logger            *slog.Logger
}

func NewEndSessionCallbackHandler(
	requestValidator validators.EndSessionRequestValidator,
	backChannelLogout services.BackchannelLogoutService,
	notifications storage.MessageStore[contexts.LogoutNotificationContext],
	clock services.SystemClock,
	options *config_options.WicketOptions,
	logger *slog.Logger,
) *EndSessionCallbackHandler {
	return &EndSessionCallbackHandler{
		requestValidator:  requestValidator,
		backChannelLogout: backChannelLogout,
		notifications:     notifications,
		clock:             clock,
		options:           options,
		logger:            logger,
	}
}

func (h *EndSessionCallbackHandler) Process(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodGet {
		return results.NewStatusCodeResult(http.StatusMethodNotAllowed).Execute(w, r)
	}
	if !h.options.Endpoints.EnableEndSessionEndpoint {
		return results.NewStatusCodeResult(http.StatusNotFound).Execute(w, r)
	}

	validationResult, err := h.requestValidator.ValidateCallback(r.Context(), r.URL.Query())
	if err != nil {
		return fmt.Errorf("validate end-session callback: %w", err)
	}
	if validationResult.Error != nil {
		return results.NewBadRequestResult(validationResult.Error, validationResult.Description).Execute(w, r)
	}

	h.sendBackChannelLogout(r)

	return results.NewEndSessionCallbackResult(validationResult).Execute(w, r)
}

// sendBackChannelLogout reads the logout context behind the callback handle and
// hands it to the back-channel logout service. Nothing here can fail the
// callback: errors are logged and the front-channel page is rendered anyway.
func (h *EndSessionCallbackHandler) sendBackChannelLogout(r *http.Request) {
	if h.backChannelLogout == nil || h.notifications == nil || h.clock == nil {
		return
	}
	message, err := h.notifications.Read(r.Context(), r.URL.Query().Get(wicket.UIConstantsDefaultRoutePathParamsEndSessionCallback))
	if err != nil {
		h.log().Warn("end-session callback: cannot read logout context for back-channel logout", slog.String("error", err.Error()))
		return
	}
	if message == nil || message.Data == nil {
		return
	}
	if time.Unix(message.Created, 0).Before(h.clock.Now().Add(-endSessionNotificationMaxAge)) {
		h.log().Debug("end-session callback: logout context too old, back-channel logout skipped")
		return
	}
	if err := h.backChannelLogout.SendLogoutNotificationsAsync(message.Data); err != nil {
		h.log().Warn("end-session callback: back-channel logout failed", slog.String("error", err.Error()))
	}
}

func (h *EndSessionCallbackHandler) log() *slog.Logger {
	if h.logger != nil {
		return h.logger
	}
	return slog.Default()
}
