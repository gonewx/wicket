// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"log/slog"
	urlpkg "net/url"
	"strings"

	"github.com/gonewx/wicket"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/models/messages"
	"github.com/gonewx/wicket/services"
	storage "github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/utils"
	"github.com/gonewx/wicket/validators"
)

type OidcReturnUrlParser struct {
	options   *config_options.WicketOptions
	validator validators.AuthorizeRequestValidator
	// httpContextAccessor accessor.HttpContextAccessor
	userSession                         services.UserSession
	urls                                services.ServerUrls
	logger                              *slog.Logger
	authorizationParametersMessageStore storage.AuthorizationParametersMessageStore
}

func NewOidcReturnUrlParser(
	options *config_options.WicketOptions,
	validator validators.AuthorizeRequestValidator,
	// httpContextAccessor accessor.HttpContextAccessor,
	userSession services.UserSession,
	urls services.ServerUrls,
	logger *slog.Logger,
	authorizationParametersMessageStore storage.AuthorizationParametersMessageStore,
) *OidcReturnUrlParser {
	return &OidcReturnUrlParser{
		options:   options,
		validator: validator,
		// httpContextAccessor: httpContextAccessor,
		userSession:                         userSession,
		urls:                                urls,
		logger:                              logger,
		authorizationParametersMessageStore: authorizationParametersMessageStore,
	}
}

// Parses a return URL.
func (p *OidcReturnUrlParser) Parse(returnUrl string) (*messages.AuthorizationRequest, error) {
	if !p.IsValidReturnUrl(returnUrl) {
		p.logger.Debug("No AuthorizationRequest being returned")

		return nil, nil
	}

	url, err := urlpkg.Parse(returnUrl)
	if err != nil {
		return nil, err
	}

	parameters := url.Query()
	if p.authorizationParametersMessageStore != nil {
		messageStoreId := parameters.Get(gois.AuthorizationParamsStoreMessageStoreIdParameterName)
		entry, err := p.authorizationParametersMessageStore.Read(messageStoreId)
		if err != nil {
			return nil, err
		}
		if entry != nil {
			parameters = entry.Data
		} else {
			parameters = urlpkg.Values{}
		}
	}

	userSession := p.userSession
	if userSession == nil {
		p.logger.Debug("user session is nil")

		return nil, nil
	}

	user := userSession.GetUser()
	result := p.validator.Validate(parameters, user)
	if result == nil {
		p.logger.Debug("No AuthorizationRequest being returned")

		return nil, nil
	}

	return messages.NewAuthorizationRequest(result.ValidatedRequest), nil
}

// Determines whether the return URL is valid.
func (p *OidcReturnUrlParser) IsValidReturnUrl(returnUrl string) bool {
	if p.options.UserInteraction.AllowOriginInReturnUrl && utils.IsUri(returnUrl) {
		host := p.urls.Origin()

		if strings.HasPrefix(strings.ToLower(returnUrl), strings.ToLower(host)) {
			returnUrl = returnUrl[len(host):]
		}
	}

	if utils.IsLocalUrl(returnUrl) {
		index := strings.IndexAny(returnUrl, "?#")
		if index >= 0 {
			returnUrl = returnUrl[:index]
		}

		if strings.HasSuffix(returnUrl, gois.ProtocolRoutePathsAuthorize) ||
			strings.HasSuffix(returnUrl, gois.ProtocolRoutePathsAuthorizeCallback) {
			p.logger.Debug("Return URL is valid")
			return true
		}
	}

	p.logger.Debug("Return URL is not valid", slog.String("returnUrl", returnUrl))
	return false
}
