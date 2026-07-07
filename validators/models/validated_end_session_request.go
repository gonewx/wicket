// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

// ValidatedEndSessionRequest Represents a validated end session (logout) request
type ValidatedEndSessionRequest struct {
	*ValidatedRequest

	// Gets or sets the post-logout URI.
	// The post-logout URI.
	PostLogOutUri string

	// Gets or sets the state.
	// The state.
	State string

	// Gets or sets the UI locales.
	// The UI locales.
	UiLocales string

	//  Ids of clients known to have an authentication session for user at end session time
	ClientIds []string
}

func NewValidatedEndSessionRequest() *ValidatedEndSessionRequest {
	return &ValidatedEndSessionRequest{
		ValidatedRequest: NewValidatedRequest(),
	}
}

// IsAuthenticated Gets a value indicating whether this instance is authenticated.
// <c>true</c> if this instance is authenticated; otherwise, <c>false</c>.
func (r *ValidatedEndSessionRequest) IsAuthenticated() bool {
	return r.Client != nil
}
