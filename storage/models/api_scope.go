// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

type ApiScope struct {
	*Resource
	Required  bool
	Emphasize bool
}

func NewApiScope() *ApiScope {
	return &ApiScope{
		Resource: NewResoure(),
	}
}
