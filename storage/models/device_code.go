// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

import (
	"time"

	"github.com/gonewx/wicket/claims"
)

// / Represents data needed for device flow.
type DeviceCode struct {
	/// Gets or sets the creation time.
	CreationTime time.Time

	/// Gets or sets the lifetime.
	Lifetime int

	/// Gets or sets the client identifier.
	ClientId string

	/// Gets the description the user assigned to the device being authorized.
	Description string

	/// Gets or sets a value indicating whether this instance is open identifier.
	IsOpenId bool

	/// Gets or sets a value indicating whether this instance is authorized.
	IsAuthorized bool

	/// Gets or sets the requested scopes.
	RequestedScopes []string

	/// Gets or sets the authorized scopes.
	AuthorizedScopes []string

	/// Gets or sets the subject.
	Subject *claims.ClaimsPrincipal

	/// Gets or sets the session identifier.
	SessionId string
}

func NewDeviceCode() *DeviceCode {
	return &DeviceCode{}
}
