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

type CustomRedirectResult struct {
	request *validators_models.ValidatedAuthorizeRequest

	options                             *options.IdentityServerOptions
	urls                                services.ServerUrls
	authorizationParametersMessageStore storage.AuthorizationParametersMessageStore
}

func NewCustomRedirectResult(
	request *validators_models.ValidatedAuthorizeRequest,
) *CustomRedirectResult {
	return &CustomRedirectResult{
		request: request,
	}
}

func (crr *CustomRedirectResult) init(ctx context.Context) {
	if crr.options == nil {
		// AD-10: CustomRedirectResult resolves options from RequestServices.
		crr.options = godi.GetRequired[*options.IdentityServerOptions](hosting.ScopeFrom(ctx))
	}

	if crr.urls == nil {
		// AD-10: CustomRedirectResult resolves ServerUrls from RequestServices.
		crr.urls = godi.GetRequired[services.ServerUrls](hosting.ScopeFrom(ctx))
	}

	if crr.authorizationParametersMessageStore == nil {
		// AD-10: results resolve optional AuthorizationParametersMessageStore from RequestServices.
		if apms, ok := godi.Get[storage.AuthorizationParametersMessageStore](hosting.ScopeFrom(ctx)); ok {
			crr.authorizationParametersMessageStore = apms
		}
	}
}

func (crr *CustomRedirectResult) Execute(w http.ResponseWriter, r *http.Request) error {
	crr.init(r.Context())

	// redirectUri, err := redirectUrl(
	// 	crr.request,
	// 	crr.options,
	// 	crr.urls,
	// 	crr.authorizationParametersMessageStore,
	// 	crr.options.UserInteraction.LoginUrl,
	// 	crr.options.UserInteraction.LoginReturnUrlParameter,
	// )

	// if err != nil {
	// 	return err
	// }

	http.Redirect(w, r, crr.request.RedirectUri, http.StatusFound)
	return nil
}
