// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package options

import (
	"net/http"
	"time"

	"github.com/gonewx/wicket"
)

// AuthenticationOptions Configures the login and logout views and behavior.
type AuthenticationOptions struct {
	//  Sets the cookie authentication scheme configured by the host used for interactive users. If not set, the scheme will inferred from the host's default authentication scheme.
	//  This setting is typically used when AddPolicyScheme is used in the host as the default scheme.
	CookieAuthenticationScheme string

	//  Sets the cookie lifetime (only effective if the built-in cookie handler is used)
	CookieLifetime time.Duration

	//  Specified if the cookie should be sliding or not (only effective if the built-in cookie middleware is used)
	CookieSlidingExpiration bool

	//  Specifies the SameSite mode for the internal authentication and temp cookie
	CookieSameSiteMode http.SameSite

	//  Indicates if user must be authenticated to accept parameters to end session endpoint. Defaults to false.
	//  <value>
	//  <c>true</c> if required; otherwise, <c>false</c>.
	//  </value>
	RequireAuthenticatedUserForSignOutMessage bool

	//  Gets or sets the name of the cookie used for the check session endpoint.
	CheckSessionCookieName string

	//  Gets or sets the domain of the cookie used for the check session endpoint. Defaults to null.
	CheckSessionCookieDomain string

	//  Gets or sets the SameSite mode of the cookie used for the check session endpoint. Defaults to SameSiteMode.None.
	CheckSessionCookieSameSiteMode http.SameSite

	//  If set, will require frame-src CSP headers being emitting on the end session callback endpoint which renders iframes to clients for front-channel sign out notification.
	RequireCspFrameSrcForSignout bool

	//  When enabled, all clients' token lifetimes (e.g. refresh tokens) will be tied to the user's session lifetime.
	//  This means when the user logs out, any revokable tokens will be removed.
	//  If using server-side sessions, expired sessions will also remove any revokable tokens, and backchannel logout will be triggered.
	//  An individual client can override this setting with its own CoordinateLifetimeWithUserSession configuration setting.
	CoordinateClientLifetimesWithUserSession bool
}

func NewAuthenticationOptions() *AuthenticationOptions {
	return &AuthenticationOptions{
		CookieLifetime:                 wicket.DefaultCookieTimeSpan,
		CheckSessionCookieName:         wicket.DefaultCheckSessionCookieName,
		CheckSessionCookieSameSiteMode: http.SameSiteNoneMode,
		RequireCspFrameSrcForSignout:   true,
	}
}
