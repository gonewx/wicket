// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

import "time"

// Consent Represents the permissions (in terms of scopes) granted to a client by a subject
type Consent struct {
	// Gets or sets the subject identifier.
	// The subject identifier.
	SubjectId string

	// Gets or sets the client identifier.
	// The client identifier.
	ClientId string

	// Gets or sets the scopes.
	// The scopes.
	Scopes []string

	// Gets or sets the creation time.
	// The creation time.
	CreationTime time.Time

	// Gets or sets the expiration.
	// The expiration.
	Expiration *time.Time
}
