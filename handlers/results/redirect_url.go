// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package results

import (
	"context"
	"fmt"
	"net/url"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/models/messages"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/utils"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// redirectUrl builds the absolute URL that hands the user agent off to an
// interaction page (login, consent, or a caller-supplied target) while carrying
// a return URL the authorize callback consumes to resume the original request.
//
// The authorize parameters ride back in one of two shapes: inlined into the
// return URL when no parameters store is wired, or written to the store and
// referenced by an opaque handle when one is. This is the forward construction
// dual to OidcReturnUrlParser.Parse, so the return URL it emits is exactly what
// that parser reads.
func redirectUrl(
	ctx context.Context,
	request *validators_models.ValidatedAuthorizeRequest,
	urls services.ServerUrls,
	apmStore storage.AuthorizationParametersMessageStore,
	targetURL string,
	returnURLParameter string,
) (string, error) {
	params := request.ToOptimizedRawValues()

	returnURL := wicket.ProtocolRoutePathsAuthorizeCallback
	if apmStore != nil {
		handle, err := apmStore.Write(ctx, messages.NewMessage[url.Values](params))
		if err != nil {
			return "", fmt.Errorf("store authorize parameters: %w", err)
		}
		returnURL = utils.AddQuery(returnURL, wicket.AuthorizationParamsStoreMessageStoreIdParameterName, handle)
	} else {
		returnURL = utils.AddQueryString(returnURL, params)
	}

	// The callback route is server-relative and carries no leading slash, so
	// normalize it unconditionally: GetWicketRelativeUrl adds the leading slash
	// the return URL parser requires to recognize a local return URL.
	returnURL = urls.GetWicketRelativeUrl(returnURL)

	target := targetURL
	if utils.IsLocalUrl(target) {
		target = utils.GetAbsoluteUrl(urls.BaseUrl(), urls.GetWicketRelativeUrl(target))
	}

	return utils.AddQueryString(target, url.Values{returnURLParameter: {returnURL}}), nil
}
