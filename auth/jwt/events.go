// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package jwt

// Events Allows subscribing to events raised during cookie authentication.
type Events struct {
	/// Invoked if authentication fails during request processing. The exceptions will be re-thrown after this event unless suppressed.
	OnAuthenticationFailed func(ctx *FailedContext) error

	/// Invoked if Authorization fails and results in a Forbidden response.
	OnForbidden func(ctx *ForbiddenContext) error

	/// Invoked after the security token has passed validation and a ClaimsIdentity has been generated.
	OnMessageReceived func(ctx *MessageReceivedContext) error

	// Invoked after sign in has completed.
	OnTokenValidated func(ctx *TokenValidatedContext) error

	// Invoked on signing out.
	OnChallenge func(ctx *ChallengeContext) error
}

func NewEvents() *Events {
	return &Events{
		OnAuthenticationFailed: func(ctx *FailedContext) error { return nil },
		OnForbidden:            func(ctx *ForbiddenContext) error { return nil },
		OnMessageReceived:      func(ctx *MessageReceivedContext) error { return nil },
		OnTokenValidated:       func(ctx *TokenValidatedContext) error { return nil },
		OnChallenge:            func(ctx *ChallengeContext) error { return nil },
	}
}

// / Invoked if exceptions are thrown during request processing. The exceptions will be re-thrown after this event unless suppressed.
func (e *Events) ValidatePrincipal(ctx *FailedContext) error {
	return e.OnAuthenticationFailed(ctx)
}

// / Invoked if Authorization fails and results in a Forbidden response
func (e *Events) Forbidden(ctx *ForbiddenContext) error {
	return e.OnForbidden(ctx)
}

// / Invoked when a protocol message is first received.
func (e *Events) MessageReceived(ctx *MessageReceivedContext) error {
	return e.OnMessageReceived(ctx)
}

// / Invoked after the security token has passed validation and a ClaimsIdentity has been generated.
func (e *Events) TokenValidated(ctx *TokenValidatedContext) error {
	return e.OnTokenValidated(ctx)
}

// / Invoked before a challenge is sent back to the caller.
func (e *Events) Challenge(ctx *ChallengeContext) error {
	return e.OnChallenge(ctx)
}
