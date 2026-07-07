// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

type DeviceAuthorizationResponse struct {
	DeviceCode              string
	UserCode                string
	VerificationUri         string
	VerificationUriComplete string
	DeviceCodeLifetime      int
	Interval                int
}
