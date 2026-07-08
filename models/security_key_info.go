// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

import (
	"github.com/gonewx/wicket/tokens"
)

type SecurityKeyInfo struct {
	// The key
	Key              tokens.SecurityKey
	SigningAlgorithm string
	// KeyId is the stable public JWKS key id. When set it is published verbatim
	// so a token header kid resolves through JWKS; when empty the JWK serializer
	// derives one from the key material.
	KeyId string
}
