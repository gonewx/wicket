// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

import (
	"time"

	"github.com/gonewx/wicket"
)

type Secret struct {
	Description string
	Value       string
	Expiration  time.Time
	Type        string
}

func NewSecret() *Secret {
	return &Secret{
		Type: wicket.SecretTypesSharedSecret,
	}
}
