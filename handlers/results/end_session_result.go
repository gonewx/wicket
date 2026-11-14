// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package results

import (
	"context"
	"net/http"

	"github.com/gonewx/godi"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/hosting"
	"github.com/gonewx/wicket/models/messages"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/utils"
	validators_models "github.com/gonewx/wicket/validators/models"
)

type EndSessionResult struct {
	result *validators_models.EndSessionValidationResult

	options            *config_options.WicketOptions
	clock              services.SystemClock
	urls               services.ServerUrls
	logoutMessageStore storage.MessageStore[messages.LogoutMessage]
}

func NewEndSessionResult(
	result *validators_models.EndSessionValidationResult,
) *EndSessionResult {
	return &EndSessionResult{
		result: result,
	}
}

func newEndSessionResult(
	result *validators_models.EndSessionValidationResult,
	options *config_options.WicketOptions,
	clock services.SystemClock,
	urls services.ServerUrls,
	logoutMessageStore storage.MessageStore[messages.LogoutMessage],
) *EndSessionResult {
	return &EndSessionResult{
		result:             result,
		options:            options,
		logoutMessageStore: logoutMessageStore,
		urls:               urls,
		clock:              clock,
	}
}

func (esr *EndSessionResult) init(ctx context.Context) {
	if esr.options == nil {
		// AD-10: EndSessionResult resolves options from RequestServices.
		esr.options = godi.GetRequired[*config_options.WicketOptions](hosting.ScopeFrom(ctx))
	}

	if esr.clock == nil {
		// AD-10: EndSessionResult resolves SystemClock from RequestServices.
		esr.clock = godi.GetRequired[services.SystemClock](hosting.ScopeFrom(ctx))
	}

	if esr.urls == nil {
		// AD-10: EndSessionResult resolves ServerUrls from RequestServices.
		esr.urls = godi.GetRequired[services.ServerUrls](hosting.ScopeFrom(ctx))
	}

	if esr.logoutMessageStore == nil {
		// AD-10: EndSessionResult resolves message stores from RequestServices.
		esr.logoutMessageStore = godi.GetRequired[storage.MessageStore[messages.LogoutMessage]](hosting.ScopeFrom(ctx))
	}

}

func (esr *EndSessionResult) Execute(w http.ResponseWriter, r *http.Request) error {
	esr.init(r.Context())

	var validatedRequest *validators_models.ValidatedEndSessionRequest

	if esr.result.Error == nil {
		validatedRequest = esr.result.ValidatedRequest
	}

	var id string
	var err error
	if validatedRequest != nil {
		logoutMessage := messages.NewLogoutMessage(validatedRequest)
		if logoutMessage.ContainsPayload() {
			msg := messages.NewMessageWithCreated(logoutMessage, esr.clock.Now().Unix())
			id, err = esr.logoutMessageStore.Write(r.Context(), msg)
		}
	}

	redirect := esr.options.UserInteraction.LogoutUrl

	if utils.IsLocalUrl(redirect) {
		redirect = esr.urls.GetWicketRelativeUrl(redirect)
	}

	if id != "" && err == nil {
		redirect = utils.AddQuery(redirect, esr.options.UserInteraction.LogoutIdParameter, id)
	}

	http.Redirect(w, r, redirect, redirectStatusCode(esr.options))
	return nil
}
