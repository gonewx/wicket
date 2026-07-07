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
}
