// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package validators_contexts

import storage_models "github.com/gonewx/wicket/storage/models"

// ClientConfigurationValidationContext Context for client configuration validation.
type ClientConfigurationValidationContext struct {
	// Gets or sets the client.
	Client *storage_models.Client

	// Returns true if client configuration is valid.
	//   <c>true</c> if this instance is valid; otherwise, <c>false</c>.
	IsValid bool

	// Gets or sets the error message.
	ErrorMessage string
}

// NewClientConfigurationValidationContext Initializes a new instance of the <see cref="ClientConfigurationValidationContext"/> class.
func NewClientConfigurationValidationContext(client *storage_models.Client) *ClientConfigurationValidationContext {
	return &ClientConfigurationValidationContext{
		Client:  client,
		IsValid: true,
	}
}

// SetError Sets a validation error.
func (c *ClientConfigurationValidationContext) SetError(message string) {
	c.IsValid = false
	c.ErrorMessage = message
}
