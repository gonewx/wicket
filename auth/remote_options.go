// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package auth

import (
	"net/http"
	"time"

	cookiespkg "github.com/gonewx/wicket/cookies"
	"github.com/gonewx/wicket/dp"
)

const (
	CorrelationPrefix = ".wicket.Correlation."
)

type RemoteOptions[T any] interface {
	SchemeOptions[T]

	// Gets or sets timeout value in milliseconds for back channel communications with the reote identity provider.
	// The back channel timeout.
	BackchannelTimeout() time.Duration
	SetBackchannelTimeout(time.Duration)

	// The HttpMessageHandler used to communicate with remote identity provider.
	// This cannot be set at the same time as BackchannelCertificateValidator unless the value
	// can be downcast to a WebRequestHandler.
	//BackchannelHttpHandler HttpMessageHandler
	BackchannelHttpHandler() http.RoundTripper
	SetBackchannelHttpHandler(http.RoundTripper)

	// Used to communicate with the remote identity provider.
	Backchannel() *http.Client
	SetBackchannel(*http.Client)

	// Gets or sets the type used to secure data.
	DataProtectionProvider() dp.DataProtectionProvider
	SetDataProtectionProvider(dp.DataProtectionProvider)

	// The request path within the application's base path where the user-agent will be returned.
	// The middleware will process this request when it arrives.
	CallbackPath() string
	SetCallbackPath(string)

	// Gets or sets the optional path the user agent is redirected to if the user
	// doesn't approve the authorization demand requested by the remote server.
	// This property is not set by default. In this case, an exception is thrown
	// if an access_denied response is returned by the remote authorization server.
	AccessDeniedPath() string
	SetAccessDeniedPath(string)

	// Gets or sets the name of the parameter used to convey the original location
	// of the user before the remote challenge was triggered up to the access denied page.
	// This property is only used when the <see cref="AccessDeniedPath"/> is explicitly spcified.
	// Note: this deliberately matches the default parameter name used by the cookie handler.
	ReturnUrlParameter() string
	SetReturnUrlParameter(string)

	// Gets or sets the authentication scheme corresponding to the middleware
	// responsible of persisting user's identity after a successful authentication.
	// This value typically corresponds to a cookie middleware registered in the Startup class.
	// When omitted, <see cref="AuthenticationOptions.DefaultSignInScheme"/> is used as a falback value.
	SignInScheme() string
	SetSignInScheme(string)

	// Gets or sets the time limit for completing the authentication flow (15 minutes by deault).
	RemoteAuthenticationTimeout() time.Duration
	SetRemoteAuthenticationTimeout(time.Duration)

	// Defines whether access and refresh tokens should be stored in the
	// <see cref="AuthenticationProperties"/> after a successful authorization.
	// This property is set to <c>false</c> by default to reduce
	// the size of the final authentication cookie.
	SaveTokens() bool
	SetSaveTokens(bool)

	CorrelationCookie() cookiespkg.Builder

	SetCorrelationCookie(value cookiespkg.Builder)
}
