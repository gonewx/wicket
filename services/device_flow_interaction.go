// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package services

import (
	"context"
	"errors"
	"time"

	"github.com/gonewx/wicket/claims"
)

// Errors returned by DeviceFlowInteractionService. They are checked in the
// order listed: an unknown user code is reported before an expired one, an
// expired one before one already handled, and only then is an approval
// checked.
var (
	// ErrDeviceFlowUserCodeNotFound reports a user code with no stored
	// device authorization, or one whose client no longer exists or is
	// disabled.
	ErrDeviceFlowUserCodeNotFound = errors.New("device flow user code not found")
	// ErrDeviceFlowUserCodeExpired reports a device authorization past its
	// lifetime.
	ErrDeviceFlowUserCodeExpired = errors.New("device flow user code expired")
	// ErrDeviceFlowUserCodeAlreadyHandled reports a device authorization that
	// was already approved or denied; a user code is handled once.
	ErrDeviceFlowUserCodeAlreadyHandled = errors.New("device flow user code already handled")
	// ErrDeviceFlowInvalidApproval reports an approval without an
	// authenticated subject, without scopes, with a scope that was not
	// requested, or without openid for an OpenID Connect request.
	ErrDeviceFlowInvalidApproval = errors.New("device flow approval is invalid")
)

// DeviceFlowAuthorizationContext describes a pending device authorization
// for the host's verification page.
type DeviceFlowAuthorizationContext struct {
	ClientId        string
	ClientName      string
	RequestedScopes []string
	IsOpenIdRequest bool
	// Expiration is when the device code and its user code expire.
	Expiration time.Time
}

// DeviceFlowInteractionService lets the host's verification page act on a
// user code (RFC 8628 §3.3): read what the device asked for, then approve or
// deny it. Every approval is an explicit decision on the page; no consent is
// remembered between device authorizations.
type DeviceFlowInteractionService interface {
	// GetAuthorizationContext returns the pending device authorization for
	// userCode.
	GetAuthorizationContext(ctx context.Context, userCode string) (*DeviceFlowAuthorizationContext, error)
	// Approve authorizes the device for subject with scopes, a non-empty
	// subset of the requested scopes that includes openid for an OpenID
	// Connect request. subject must carry a sub claim; its claims flow into
	// the issued tokens. sessionId may be empty.
	Approve(ctx context.Context, userCode string, subject *claims.ClaimsPrincipal, sessionId string, scopes []string) error
	// Deny rejects the device authorization; the device's next poll answers
	// access_denied.
	Deny(ctx context.Context, userCode string) error
}
