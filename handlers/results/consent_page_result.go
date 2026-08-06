// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package results

import (
	"context"
	"net/http"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/hosting"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/storage"
	validators_models "github.com/gonewx/wicket/validators/models"
)

type ConsentPageResult struct {
	request *validators_models.ValidatedAuthorizeRequest

	options                             *options.WicketOptions
	urls                                services.ServerUrls
	authorizationParametersMessageStore storage.AuthorizationParametersMessageStore
}

func NewConsentPageResult(
	request *validators_models.ValidatedAuthorizeRequest,
) *ConsentPageResult {
	return &ConsentPageResult{
		request: request,
	}
}

func (cpr *ConsentPageResult) init(ctx context.Context) {
	if cpr.options == nil {
		// AD-10: ConsentPageResult resolves options from RequestServices.
		cpr.options = godi.GetRequired[*options.WicketOptions](hosting.ScopeFrom(ctx))
	}

	if cpr.urls == nil {
		// AD-10: ConsentPageResult resolves ServerUrls from RequestServices.
		cpr.urls = godi.GetRequired[services.ServerUrls](hosting.ScopeFrom(ctx))
	}

	if cpr.authorizationParametersMessageStore == nil {
		// AD-10: results resolve optional AuthorizationParametersMessageStore from RequestServices.
		if apms, ok := godi.Get[storage.AuthorizationParametersMessageStore](hosting.ScopeFrom(ctx)); ok {
			cpr.authorizationParametersMessageStore = apms
		}
	}
}

func (cpr *ConsentPageResult) Execute(w http.ResponseWriter, r *http.Request) error {
	cpr.init(r.Context())

	target, err := redirectUrl(
		r.Context(),
		cpr.request,
		cpr.urls,
		cpr.authorizationParametersMessageStore,
		cpr.options.UserInteraction.ConsentUrl,
		cpr.options.UserInteraction.ConsentReturnUrlParameter,
	)
	if err != nil {
		return err
	}

	http.Redirect(w, r, target, http.StatusFound)
	return nil
}
