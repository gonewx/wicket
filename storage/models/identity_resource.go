// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

type IdentityResource struct {
	*Resource
	Required  bool
	Emphasize bool
}

func NewIdentityResource() *IdentityResource {
	return &IdentityResource{
		Resource: NewResoure(),
	}
}
