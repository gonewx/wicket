// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package contexts

import (
	"github.com/gonewx/wicket/claims"
	storage_models "github.com/gonewx/wicket/storage/models"
)

// IsActiveContext describing the is-active check
type IsActiveContext struct {
	// Subject.
	Subject *claims.ClaimsPrincipal

	Client *storage_models.Client

	Caller string

	IsActive bool
}

// Initializes a new instance of the IsActiveContext.
func NewIsActiveContext(subject *claims.ClaimsPrincipal, client *storage_models.Client, caller string) *IsActiveContext {
	return &IsActiveContext{
		Subject:  subject,
		Client:   client,
		Caller:   caller,
		IsActive: true,
	}
}
