// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

import "time"

// PersistedGrant A model for a persisted grant
type PersistedGrant struct {
	/// Gets or sets the key.
	Key string

	/// Gets the type.
	Type string

	/// Gets the subject identifier.
	SubjectId string

	/// Gets the session identifier.
	SessionId string

	/// Gets the client identifier.
	ClientId string

	/// Gets the description the user assigned to the device being authorized.
	Description string

	/// Gets or sets the creation time.
	CreationTime time.Time

	/// Gets or sets the expiration.
	Expiration *time.Time

	/// Gets or sets the consumed time.
	ConsumedTime *time.Time

	/// Gets or sets the data.
	Data []byte
}
