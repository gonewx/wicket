// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package auth

import (
	"net/http"

	optspkg "github.com/gonewx/wicket/di/options"
)

type SchemeOptions[T any] interface {
	optspkg.Entity[T]

	// Check that the options are valid. Should throw an exception if things are not ok.
	Validate() error

	// Checks that the options are valid for a specific scheme
	ValidateByScheme(scheme string) error

	// Gets or sets the issuer that should be used for any claims. that are created
	ClaimsIssuer() string
	SetClaimsIssuer(value string)

	// Instance used for events
	Events() any
	SetEvents(value any)

	// If set, this specifies a default scheme that authentication handlers should forward all authentication operations to
	// by default. The default forwarding logic will check the most specific ForwardAuthenticate/Challenge/Forbid/SignIn/SignOut
	// setting first, followed by checking the ForwardDefaultSelector, followed by ForwardDefault. The first non null result
	// will be used as the target scheme to forward to.
	ForwardDefault() string
	SetForwardDefault(value string)

	// If set, this specifies the target scheme that this scheme should forward AuthenticateAsync calls to.
	// For example Context.AuthenticateAsync("ThisScheme") => Context.AuthenticateAsync("ForwardAuthenticateValue");
	// Set the target to the current scheme to disable forwarding and allow normal processing.
	ForwardAuthenticate() string
	SetForwardAuthenticate(value string)

	// If set, this specifies the target scheme that this scheme should forward ChallengeAsync calls to.
	// For example Context.ChallengeAsync("ThisScheme") => Context.ChallengeAsync("ForwardChallengeValue");
	// Set the target to the current scheme to disable forwarding and allow normal processing.
	ForwardChallenge() string
	SetForwardChallenge(value string)

	// If set, this specifies the target scheme that this scheme should forward ForbidAsync calls to.
	// For example Context.ForbidAsync("ThisScheme") => Context.ForbidAsync("ForwardForbidValue");
	// Set the target to the current scheme to disable forwarding and allow normal processing.
	ForwardForbid() string
	SetForwardForbid(value string)

	// If set, this specifies the target scheme that this scheme should forward SignInAsync calls to.
	// For example Context.SignInAsync("ThisScheme") => Context.SignInAsync("ForwardSignInValue");
	// Set the target to the current scheme to disable forwarding and allow normal processing.
	ForwardSignIn() string
	SetForwardSignIn(value string)

	// If set, this specifies the target scheme that this scheme should forward SignOutAsync calls to.
	// For example Context.SignOutAsync("ThisScheme") => Context.SignOutAsync("ForwardSignOutValue");
	// Set the target to the current scheme to disable forwarding and allow normal processing.
	ForwardSignOut() string
	SetForwardSignOut(value string)

	// Used to select a default scheme for the current request that authentication handlers should forward all authentication operations to
	// by default. The default forwarding logic will check the most specific ForwardAuthenticate/Challenge/Forbid/SignIn/SignOut
	// setting first, followed by checking the ForwardDefaultSelector, followed by ForwardDefault. The first non null result
	// will be used as the target scheme to forward to.
	ForwardDefaultSelector() func(*http.Request) string
	SetForwardDefaultSelector(value func(*http.Request) string)
}
