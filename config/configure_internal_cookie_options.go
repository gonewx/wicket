// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package config

import (
	"log/slog"
	"strings"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/auth"
	authcookies "github.com/gonewx/wicket/auth/cookies"
	"github.com/gonewx/wicket/config/options"
	optspkg "github.com/gonewx/wicket/options"
	"github.com/gonewx/wicket/utils"
)

type ConfigureInternalCookieOptions struct {
	idsrv *options.IdentityServerOptions
}

func NewConfigureInternalCookieOptions(idsrv *options.IdentityServerOptions) *ConfigureInternalCookieOptions {
	return &ConfigureInternalCookieOptions{idsrv: idsrv}
}

func (o *ConfigureInternalCookieOptions) Configure(options *authcookies.AuthenticationOptions) error {
	return nil
}

func (o *ConfigureInternalCookieOptions) ConfigureWithName(name string, options *authcookies.AuthenticationOptions) error {
	if name == gois.DefaultCookieAuthenticationScheme {
		options.SlidingExpiration = o.idsrv.Authentication.CookieSlidingExpiration
		options.ExpireTimeSpan = o.idsrv.Authentication.CookieLifetime
		options.Cookie().SetName(gois.DefaultCookieAuthenticationScheme)
		options.Cookie().SetIsEssential(true)
		options.Cookie().SetSameSite(o.idsrv.Authentication.CookieSameSiteMode)

		options.LoginPath = extractLocalUrl(o.idsrv.UserInteraction.LoginUrl)
		options.LogoutPath = extractLocalUrl(o.idsrv.UserInteraction.LogoutUrl)
		if o.idsrv.UserInteraction.LoginReturnUrlParameter != "" {
			options.ReturnUrlParameter = o.idsrv.UserInteraction.LoginReturnUrlParameter
		}
	}

	if name == gois.ExternalCookieAuthenticationScheme {
		options.Cookie().SetName(gois.ExternalCookieAuthenticationScheme)
		options.Cookie().SetIsEssential(true)
		// https://github.com/IdentityServer/IdentityServer4/issues/2595
		// need to set None because iOS 12 safari considers the POST back to the client from the
		// IdP as not safe, so cookies issued from response (with lax) then should not be honored.
		// so we need to make those cookies issued without same-site, thus the browser will
		// hold onto them and send on the next redirect to the callback page.
		// see: https://brockallen.com/2019/01/11/same-site-cookies-asp-net-core-and-external-authentication-providers/
		options.Cookie().SetSameSite(o.idsrv.Authentication.CookieSameSiteMode)
	}

	return nil
}

func extractLocalUrl(url string) string {
	if utils.IsLocalUrl(url) {
		if strings.HasPrefix(url, "~/") {
			url = url[1:]
		}

		return url
	}

	return ""
}

type PostConfigureInternalCookieOptions struct {
	idsrv       *options.IdentityServerOptions
	authOptions optspkg.Options[*auth.Options]
	logger      *slog.Logger
}

func NewPostConfigureInternalCookieOptions(
	idsrv *options.IdentityServerOptions,
	authOptions optspkg.Options[*auth.Options],
	logger *slog.Logger) *PostConfigureInternalCookieOptions {
	return &PostConfigureInternalCookieOptions{
		idsrv:       idsrv,
		authOptions: authOptions,
		logger:      logger,
	}
}

func (p *PostConfigureInternalCookieOptions) PostConfigure(name string, options *authcookies.AuthenticationOptions) error {
	scheme := p.idsrv.Authentication.CookieAuthenticationScheme
	if scheme == "" {
		v, err := p.authOptions.Value()
		if err != nil {
			panic(err)
		}

		scheme = v.DefaultAuthenticateScheme
		if scheme == "" {
			scheme = v.DefaultScheme
		}
	}

	if name == scheme {
		if p.idsrv.UserInteraction.LoginUrl == "" {
			p.idsrv.UserInteraction.LoginUrl = options.LoginPath
		}
		if p.idsrv.UserInteraction.LoginReturnUrlParameter == "" {
			p.idsrv.UserInteraction.LoginReturnUrlParameter = options.ReturnUrlParameter
		}
		if p.idsrv.UserInteraction.LogoutUrl == "" {
			p.idsrv.UserInteraction.LogoutUrl = options.LogoutPath
		}

		// p.logger.Debug("Login Url: ", slog.String("url", p.idsrv.UserInteraction.LoginUrl))
		// p.logger.Debug("Login Return Url Parameter: ", slog.String("param", p.idsrv.UserInteraction.LoginReturnUrlParameter))
		// p.logger.Debug("Logout Url: ", slog.String("url", p.idsrv.UserInteraction.LogoutUrl))

		// p.logger.Debug("ConsentUrl Url: ", slog.String("url", p.idsrv.UserInteraction.ConsentUrl))
		// p.logger.Debug("Consent Return Url Parameter: ", slog.String("param", p.idsrv.UserInteraction.ConsentReturnUrlParameter))

		// p.logger.Debug("Error Url: ", slog.String("url", p.idsrv.UserInteraction.ErrorUrl))
		// p.logger.Debug("Error Id Parameter: ", slog.String("param", p.idsrv.UserInteraction.ErrorIdParameter))
	}

	return nil
}
