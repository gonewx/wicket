// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package core

import (
	"net/http"

	"github.com/gonewx/wicket/auth"
)

var _ auth.SchemeOptions[*SchemeOptions] = (*SchemeOptions)(nil)

// var _ optspkg.Creator[*SchemeOptions] = (*SchemeOptions)(nil)

type SchemeOptions struct {
	// Gets or sets the issuer that should be used for any claims. that are created
	claimsIssuer string

	// Instance used for events
	events any

	// If set, this specifies a default scheme that authentication handlers should forward all authentication operations to
	// by default. The default forwarding logic will check the most specific ForwardAuthenticate/Challenge/Forbid/SignIn/SignOut
	// setting first, followed by checking the ForwardDefaultSelector, followed by ForwardDefault. The first non null result
	// will be used as the target scheme to forward to.
	forwardDefault string

	// If set, this specifies the target scheme that this scheme should forward AuthenticateAsync calls to.
	// For example Context.AuthenticateAsync("ThisScheme") => Context.AuthenticateAsync("ForwardAuthenticateValue");
	// Set the target to the current scheme to disable forwarding and allow normal processing.
	forwardAuthenticate string

	// If set, this specifies the target scheme that this scheme should forward ChallengeAsync calls to.
	// For example Context.ChallengeAsync("ThisScheme") => Context.ChallengeAsync("ForwardChallengeValue");
	// Set the target to the current scheme to disable forwarding and allow normal processing.
	forwardChallenge string

	// If set, this specifies the target scheme that this scheme should forward ForbidAsync calls to.
	// For example Context.ForbidAsync("ThisScheme") => Context.ForbidAsync("ForwardForbidValue");
	// Set the target to the current scheme to disable forwarding and allow normal processing.
	forwardForbid string

	// If set, this specifies the target scheme that this scheme should forward SignInAsync calls to.
	// For example Context.SignInAsync("ThisScheme") => Context.SignInAsync("ForwardSignInValue");
	// Set the target to the current scheme to disable forwarding and allow normal processing.
	forwardSignIn string

	// If set, this specifies the target scheme that this scheme should forward SignOutAsync calls to.
	// For example Context.SignOutAsync("ThisScheme") => Context.SignOutAsync("ForwardSignOutValue");
	// Set the target to the current scheme to disable forwarding and allow normal processing.
	forwardSignOut string

	// Used to select a default scheme for the current request that authentication handlers should forward all authentication operations to
	// by default. The default forwarding logic will check the most specific ForwardAuthenticate/Challenge/Forbid/SignIn/SignOut
	// setting first, followed by checking the ForwardDefaultSelector, followed by ForwardDefault. The first non null result
	// will be used as the target scheme to forward to.
	forwardDefaultSelector func(*http.Request) string
}

func NewSchemeOptions() *SchemeOptions {
	return &SchemeOptions{}
}

func (*SchemeOptions) New() *SchemeOptions {
	return NewSchemeOptions()
}

func (o *SchemeOptions) Validate() error {
	return nil
}

func (o *SchemeOptions) ValidateByScheme(scheme string) error {
	return o.Validate()
}

// Gets or sets the issuer that should be used for any claims. that are created
func (o *SchemeOptions) ClaimsIssuer() string {
	return o.claimsIssuer
}

func (o *SchemeOptions) SetClaimsIssuer(value string) {
	o.claimsIssuer = value
}

func (o *SchemeOptions) Events() any {
	return o.events
}

func (o *SchemeOptions) SetEvents(value any) {
	o.events = value
}

// If set, this specifies a default scheme that authentication handlers should forward all authentication operations to
// by default. The default forwarding logic will check the most specific ForwardAuthenticate/Challenge/Forbid/SignIn/SignOut
// setting first, followed by checking the ForwardDefaultSelector, followed by ForwardDefault. The first non null result
// will be used as the target scheme to forward to.
func (o *SchemeOptions) ForwardDefault() string {
	return o.forwardDefault
}

func (o *SchemeOptions) SetForwardDefault(value string) {
	o.forwardDefault = value
}

// If set, this specifies the target scheme that this scheme should forward AuthenticateAsync calls to.
// For example Context.AuthenticateAsync("ThisScheme") => Context.AuthenticateAsync("ForwardAuthenticateValue");
// Set the target to the current scheme to disable forwarding and allow normal processing.
func (o *SchemeOptions) ForwardAuthenticate() string {
	return o.forwardAuthenticate
}

func (o *SchemeOptions) SetForwardAuthenticate(value string) {
	o.forwardAuthenticate = value
}

// If set, this specifies the target scheme that this scheme should forward ChallengeAsync calls to.
// For example Context.ChallengeAsync("ThisScheme") => Context.ChallengeAsync("ForwardChallengeValue");
// Set the target to the current scheme to disable forwarding and allow normal processing.
func (o *SchemeOptions) ForwardChallenge() string {
	return o.forwardChallenge
}

func (o *SchemeOptions) SetForwardChallenge(value string) {
	o.forwardChallenge = value
}

// If set, this specifies the target scheme that this scheme should forward ForbidAsync calls to.
// For example Context.ForbidAsync("ThisScheme") => Context.ForbidAsync("ForwardForbidValue");
// Set the target to the current scheme to disable forwarding and allow normal processing.
func (o *SchemeOptions) ForwardForbid() string {
	return o.forwardForbid
}

func (o *SchemeOptions) SetForwardForbid(value string) {
	o.forwardForbid = value
}

// If set, this specifies the target scheme that this scheme should forward SignInAsync calls to.
// For example Context.SignInAsync("ThisScheme") => Context.SignInAsync("ForwardSignInValue");
// Set the target to the current scheme to disable forwarding and allow normal processing.
func (o *SchemeOptions) ForwardSignIn() string {
	return o.forwardSignIn
}

func (o *SchemeOptions) SetForwardSignIn(value string) {
	o.forwardSignIn = value
}

// If set, this specifies the target scheme that this scheme should forward SignOutAsync calls to.
// For example Context.SignOutAsync("ThisScheme") => Context.SignOutAsync("ForwardSignOutValue");
// Set the target to the current scheme to disable forwarding and allow normal processing.
func (o *SchemeOptions) ForwardSignOut() string {
	return o.forwardSignOut
}

func (o *SchemeOptions) SetForwardSignOut(value string) {
	o.forwardSignOut = value
}

// Used to select a default scheme for the current request that authentication handlers should forward all authentication operations to
// by default. The default forwarding logic will check the most specific ForwardAuthenticate/Challenge/Forbid/SignIn/SignOut
// setting first, followed by checking the ForwardDefaultSelector, followed by ForwardDefault. The first non null result
// will be used as the target scheme to forward to.
func (o *SchemeOptions) ForwardDefaultSelector() func(*http.Request) string {
	return o.forwardDefaultSelector
}

func (o *SchemeOptions) SetForwardDefaultSelector(value func(*http.Request) string) {
	o.forwardDefaultSelector = value
}
