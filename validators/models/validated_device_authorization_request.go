// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

// Models a validated request to the token endpoint.
type ValidatedDeviceAuthorizationRequest struct {
	*ValidatedRequest

	// Gets or sets the scopes.
	RequestedScopes []string

	// Gets or sets a value indicating whether this instance is open identifier request.
	//  true if this instance is open identifier request; otherwise, false.
	IsOpenIdRequest bool

	// Gets the description the user assigned to the device being authorized.
	Description string
}

func NewValidatedDeviceAuthorizationRequest() *ValidatedDeviceAuthorizationRequest {
	return &ValidatedDeviceAuthorizationRequest{
		ValidatedRequest: NewValidatedRequest(),
	}
}
