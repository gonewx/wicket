// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

type Resource struct {
	Enabled                 bool
	Name                    string
	DisplayName             string
	Description             string
	ShowInDiscoveryDocument bool
	UserClaims              []string
	Properties              map[string]string
}

func NewResoure() *Resource {
	return &Resource{
		Enabled:                 true,
		ShowInDiscoveryDocument: true,
	}
}
