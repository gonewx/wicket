// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package auth

type Token struct {
	Name  string `json:"name,omitempty"`
	Value string `json:"value,omitempty"`
}
