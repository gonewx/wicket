// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package protocols

// Grant types for token requests. See http://tools.ietf.org/html/rfc6749.
const (
	GrantTypesAuthorizationCode = "authorization_code"
	GrantTypesRefreshToken      = "refresh_token"
	GrantTypesPassword          = "password"
	GrantTypesClientCredentials = "client_credentials"
)
