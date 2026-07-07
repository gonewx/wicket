// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package messages

// AuthorizationError Enum to model interaction authorization errors.
type AuthorizationError int

const (
	// Access denied
	AccessDenied AuthorizationError = iota

	// Interaction required
	InteractionRequired

	// Login required
	LoginRequired

	// Account selection required
	AccountSelectionRequired

	// Consent required
	ConsentRequired

	// Temporarily unavailable
	TemporarilyUnavailable
)

// ConsentResponse Models the user's response to the consent screen.
type ConsentResponse struct {
	// Error, if any, for the consent response.
	Error *AuthorizationError

	// Error description.
	ErrorDescription string

	// Gets or sets the scope values consented to.
	// The scopes.
	ScopesValuesConsented []string

	// Gets or sets a value indicating whether the user wishes the consent to be remembered.
	// true if consent is to be remembered; otherwise, false.
	RememberConsent bool

	// Gets the description of the device.
	// The description of the device.
	Description string
}

func NewConsentResponse() *ConsentResponse {
	return &ConsentResponse{}
}

// Granted Gets if consent was granted.
// true if consent was granted; otherwise, false.
func (r *ConsentResponse) Granted() bool {
	return r.ScopesValuesConsented != nil && len(r.ScopesValuesConsented) > 0 && r.Error == nil
}
