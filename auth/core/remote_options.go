// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package core

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gonewx/wicket"
	cookiespkg "github.com/gonewx/wicket/cookies"
	"github.com/gonewx/wicket/dp"
)

const (
	CorrelationPrefix = ".wicket.Correlation."
)

// var _ optspkg.Creator[*RemoteOptions] = (*RemoteOptions)(nil)

type RemoteOptions struct {
	*SchemeOptions

	correlationCookieBuilder *correlationCookieBuilder

	// Gets or sets timeout value in milliseconds for back channel communications with the reote identity provider.
	// The back channel timeout.
	backchannelTimeout time.Duration

	// The HttpMessageHandler used to communicate with remote identity provider.
	// This cannot be set at the same time as BackchannelCertificateValidator unless the value
	// can be downcast to a WebRequestHandler.
	backchannelHttpHandler http.RoundTripper

	// Used to communicate with the remote identity provider.
	backchannel *http.Client

	// Gets or sets the type used to secure data.
	dataProtectionProvider dp.DataProtectionProvider

	// The request path within the application's base path where the user-agent will be returned.
	// The middleware will process this request when it arrives.
	callbackPath string

	// Gets or sets the optional path the user agent is redirected to if the user
	// doesn't approve the authorization demand requested by the remote server.
	// This property is not set by default. In this case, an exception is thrown
	// if an access_denied response is returned by the remote authorization server.
	accessDeniedPath string

	// Gets or sets the name of the parameter used to convey the original location
	// of the user before the remote challenge was triggered up to the access denied page.
	// This property is only used when the <see cref="AccessDeniedPath"/> is explicitly spcified.
	// Note: this deliberately matches the default parameter name used by the cookie handler.
	returnUrlParameter string

	// Gets or sets the authentication scheme corresponding to the middleware
	// responsible of persisting user's identity after a successful authentication.
	// This value typically corresponds to a cookie middleware registered in the Startup class.
	// When omitted, <see cref="AuthenticationOptions.DefaultSignInScheme"/> is used as a falback value.
	signInScheme string

	// Gets or sets the time limit for completing the authentication flow (15 minutes by deault).
	remoteAuthenticationTimeout time.Duration

	// Defines whether access and refresh tokens should be stored in the
	// <see cref="AuthenticationProperties"/> after a successful authorization.
	// This property is set to <c>false</c> by default to reduce
	// the size of the final authentication cookie.
	saveTokens bool
}

func NewRemoteOptions() *RemoteOptions {
	o := &RemoteOptions{
		SchemeOptions:               NewSchemeOptions(),
		backchannelTimeout:          time.Duration(60) * time.Second,
		returnUrlParameter:          "ReturnUrl",
		remoteAuthenticationTimeout: time.Duration(15) * time.Minute,
	}

	o.correlationCookieBuilder = newCorrelationCookieBuilder(o)
	o.correlationCookieBuilder.SetName(CorrelationPrefix)
	o.correlationCookieBuilder.HttpOnly = true
	o.correlationCookieBuilder.SetSameSite(http.SameSiteNoneMode)
	o.correlationCookieBuilder.SetSecurePolicy(cookiespkg.CookieSecurePolicySameAsRequest)
	o.correlationCookieBuilder.SetIsEssential(true)

	return o
}

func (*RemoteOptions) New() *RemoteOptions {
	return NewRemoteOptions()
}

// ValidateByScheme Checks that the options are valid for a specific scheme
func (ro *RemoteOptions) ValidateByScheme(scheme string) error {
	if err := ro.SchemeOptions.ValidateByScheme(scheme); err != nil {
		return err
	}

	if scheme == ro.signInScheme {
		return fmt.Errorf("The SignInScheme for a remote authentication handler cannot be set to itself.  If it was not explicitly set, the AuthenticationOptions.DefaultSignInScheme or DefaultScheme is used. %w", wicket.InvalidOperationException)
	}

	return nil
}

// Validate Check that the options are valid.  Should throw an exception if things are not ok.
func (ro *RemoteOptions) Validate() error {
	if err := ro.SchemeOptions.Validate(); err != nil {
		return err
	}

	if ro.callbackPath == "" {
		return fmt.Errorf("The CallbackPath option must be provided. %w", wicket.ArgumentNullException)
	}

	return nil
}

// CorrelationCookie Determines the settings used to create the correlation cookie before the
// cookie gets added to the response.
func (ro *RemoteOptions) CorrelationCookie() cookiespkg.Builder {
	return ro.correlationCookieBuilder
}

func (ro *RemoteOptions) SetCorrelationCookie(value cookiespkg.Builder) {
	ro.correlationCookieBuilder = value.(*correlationCookieBuilder)
}

func (ro *RemoteOptions) BackchannelHttpHandler() http.RoundTripper {
	return ro.backchannelHttpHandler
}

func (ro *RemoteOptions) SetBackchannelHttpHandler(bchh http.RoundTripper) {
	ro.backchannelHttpHandler = bchh
}

func (ro *RemoteOptions) BackchannelTimeout() time.Duration {
	return ro.backchannelTimeout
}
func (ro *RemoteOptions) SetBackchannelTimeout(bct time.Duration) {
	ro.backchannelTimeout = bct
}

func (ro *RemoteOptions) Backchannel() *http.Client {
	return ro.backchannel
}
func (ro *RemoteOptions) SetBackchannel(bc *http.Client) {
	ro.backchannel = bc
}

func (ro *RemoteOptions) DataProtectionProvider() dp.DataProtectionProvider {
	return ro.dataProtectionProvider
}
func (ro *RemoteOptions) SetDataProtectionProvider(dpp dp.DataProtectionProvider) {
	ro.dataProtectionProvider = dpp
}

func (ro *RemoteOptions) CallbackPath() string {
	return ro.callbackPath
}
func (ro *RemoteOptions) SetCallbackPath(cbp string) {
	ro.callbackPath = cbp
}

func (ro *RemoteOptions) AccessDeniedPath() string {
	return ro.accessDeniedPath
}
func (ro *RemoteOptions) SetAccessDeniedPath(adp string) {
	ro.accessDeniedPath = adp
}

func (ro *RemoteOptions) ReturnUrlParameter() string {
	return ro.returnUrlParameter
}
func (ro *RemoteOptions) SetReturnUrlParameter(rup string) {
	ro.returnUrlParameter = rup
}

func (ro *RemoteOptions) SignInScheme() string {
	return ro.signInScheme
}
func (ro *RemoteOptions) SetSignInScheme(sis string) {
	ro.signInScheme = sis
}

func (ro *RemoteOptions) RemoteAuthenticationTimeout() time.Duration {
	return ro.remoteAuthenticationTimeout
}
func (ro *RemoteOptions) SetRemoteAuthenticationTimeout(rat time.Duration) {
	ro.remoteAuthenticationTimeout = rat
}

func (ro *RemoteOptions) SaveTokens() bool {
	return ro.saveTokens
}
func (ro *RemoteOptions) SetSaveTokens(st bool) {
	ro.saveTokens = st
}

type correlationCookieBuilder struct {
	*RequestPathBaseBuilder

	opts *RemoteOptions
}

func newCorrelationCookieBuilder(opts *RemoteOptions) *correlationCookieBuilder {
	b := &correlationCookieBuilder{

		opts: opts,
	}

	b.RequestPathBaseBuilder = NewRequestPathBaseBuilder()

	return b
}

func (ccb *correlationCookieBuilder) AdditionalPath() string {
	return ccb.opts.callbackPath
}

func (ccb *correlationCookieBuilder) Build(req *http.Request) *cookiespkg.Options {
	ccb.RequestPathBaseBuilder.AdditionalPath = ccb.AdditionalPath()
	return ccb.RequestPathBaseBuilder.BuildWithExpires(req, ccb.Now())
}

func (ccb *correlationCookieBuilder) BuildWithExpires(req *http.Request, expiresFrom time.Time) *cookiespkg.Options {
	ccb.RequestPathBaseBuilder.AdditionalPath = ccb.AdditionalPath()
	return ccb.RequestPathBaseBuilder.BuildWithExpires(req, expiresFrom)
}
