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
	optspkg "github.com/gonewx/wicket/di/options"
	"github.com/gonewx/wicket/utils"
)

type ConfigureInternalCookieOptions struct {
	wicket *options.WicketOptions
}

func NewConfigureInternalCookieOptions(wicket *options.WicketOptions) *ConfigureInternalCookieOptions {
	return &ConfigureInternalCookieOptions{wicket: wicket}
}

func (o *ConfigureInternalCookieOptions) Configure(options *authcookies.AuthenticationOptions) error {
	return nil
}

func (o *ConfigureInternalCookieOptions) ConfigureWithName(name string, options *authcookies.AuthenticationOptions) error {
	if name == wicket.DefaultCookieAuthenticationScheme {
		options.SlidingExpiration = o.wicket.Authentication.CookieSlidingExpiration
		options.ExpireTimeSpan = o.wicket.Authentication.CookieLifetime
		options.Cookie().SetName(wicket.DefaultCookieAuthenticationScheme)
		options.Cookie().SetIsEssential(true)
		options.Cookie().SetSameSite(o.wicket.Authentication.CookieSameSiteMode)

		options.LoginPath = extractLocalUrl(o.wicket.UserInteraction.LoginUrl)
		options.LogoutPath = extractLocalUrl(o.wicket.UserInteraction.LogoutUrl)
		if o.wicket.UserInteraction.LoginReturnUrlParameter != "" {
			options.ReturnUrlParameter = o.wicket.UserInteraction.LoginReturnUrlParameter
		}
	}

	if name == wicket.ExternalCookieAuthenticationScheme {
		options.Cookie().SetName(wicket.ExternalCookieAuthenticationScheme)
		options.Cookie().SetIsEssential(true)
		// need to set None because iOS 12 safari considers the POST back to the client from the
		// IdP as not safe, so cookies issued from response (with lax) then should not be honored.
		// so we need to make those cookies issued without same-site, thus the browser will
		// hold onto them and send on the next redirect to the callback page.
		// see: https://brockallen.com/2019/01/11/same-site-cookies-asp-net-core-and-external-authentication-providers/
		options.Cookie().SetSameSite(o.wicket.Authentication.CookieSameSiteMode)
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
	wicket      *options.WicketOptions
	authOptions optspkg.Options[*auth.Options]
	logger      *slog.Logger
}

func NewPostConfigureInternalCookieOptions(
	wicket *options.WicketOptions,
	authOptions optspkg.Options[*auth.Options],
	logger *slog.Logger) *PostConfigureInternalCookieOptions {
	return &PostConfigureInternalCookieOptions{
		wicket:      wicket,
		authOptions: authOptions,
		logger:      logger,
	}
}

func (p *PostConfigureInternalCookieOptions) PostConfigure(name string, options *authcookies.AuthenticationOptions) error {
	scheme := p.wicket.Authentication.CookieAuthenticationScheme
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
		if p.wicket.UserInteraction.LoginUrl == "" {
			p.wicket.UserInteraction.LoginUrl = options.LoginPath
		}
		if p.wicket.UserInteraction.LoginReturnUrlParameter == "" {
			p.wicket.UserInteraction.LoginReturnUrlParameter = options.ReturnUrlParameter
		}
		if p.wicket.UserInteraction.LogoutUrl == "" {
			p.wicket.UserInteraction.LogoutUrl = options.LogoutPath
		}

		// p.logger.Debug("Login Url: ", slog.String("url", p.wicket.UserInteraction.LoginUrl))
		// p.logger.Debug("Login Return Url Parameter: ", slog.String("param", p.wicket.UserInteraction.LoginReturnUrlParameter))
		// p.logger.Debug("Logout Url: ", slog.String("url", p.wicket.UserInteraction.LogoutUrl))

		// p.logger.Debug("ConsentUrl Url: ", slog.String("url", p.wicket.UserInteraction.ConsentUrl))
		// p.logger.Debug("Consent Return Url Parameter: ", slog.String("param", p.wicket.UserInteraction.ConsentReturnUrlParameter))

		// p.logger.Debug("Error Url: ", slog.String("url", p.wicket.UserInteraction.ErrorUrl))
		// p.logger.Debug("Error Id Parameter: ", slog.String("param", p.wicket.UserInteraction.ErrorIdParameter))
	}

	return nil
}
