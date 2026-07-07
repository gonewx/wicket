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

type LoginPageResult struct {
	request *validators_models.ValidatedAuthorizeRequest

	options                             *options.WicketOptions
	urls                                services.ServerUrls
	authorizationParametersMessageStore storage.AuthorizationParametersMessageStore
}

func NewLoginPageResult(
	request *validators_models.ValidatedAuthorizeRequest,
) *LoginPageResult {
	return &LoginPageResult{
		request: request,
	}
}

func (lpr *LoginPageResult) init(ctx context.Context) {
	if lpr.options == nil {
		// AD-10: LoginPageResult resolves options from RequestServices.
		lpr.options = godi.GetRequired[*options.WicketOptions](hosting.ScopeFrom(ctx))
	}

	if lpr.urls == nil {
		// AD-10: LoginPageResult resolves ServerUrls from RequestServices.
		lpr.urls = godi.GetRequired[services.ServerUrls](hosting.ScopeFrom(ctx))
	}

	if lpr.authorizationParametersMessageStore == nil {
		// AD-10: results resolve optional AuthorizationParametersMessageStore from RequestServices.
		if apms, ok := godi.Get[storage.AuthorizationParametersMessageStore](hosting.ScopeFrom(ctx)); ok {
			lpr.authorizationParametersMessageStore = apms
		}
	}
}

func (lpr *LoginPageResult) Execute(w http.ResponseWriter, r *http.Request) error {
	lpr.init(r.Context())

	http.Redirect(w, r, lpr.request.RedirectUri, http.StatusFound)
	return nil
}
