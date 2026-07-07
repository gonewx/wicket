// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

type ParsedSecret struct {
	Id         string
	Credential string
	Type       string
	Properties map[string]string
}
