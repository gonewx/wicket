// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package options

// From: IdentityServer4/src/Storage/Stores/Serialization/PersistentGrantSerializer.cs

// PersistentGrantOptions Options for how persisted grants are persisted.
type PersistentGrantOptions struct {
	DataProtectData bool
}

func NewPersistentGrantOptions() *PersistentGrantOptions {
	return &PersistentGrantOptions{
		DataProtectData: true,
	}
}
