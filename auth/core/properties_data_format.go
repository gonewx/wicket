// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package core

import (
	"github.com/gonewx/wicket/auth"
	"github.com/gonewx/wicket/dp"
)

type PropertiesDataFormat struct {
	SecureDataFormat[auth.Properties]
}

func NewPropertiesDataFormat(protector dp.DataProtector) *PropertiesDataFormat {
	base := NewPropertiesSerializer()
	return &PropertiesDataFormat{
		SecureDataFormat: NewSecureDataFormat[auth.Properties](base, protector),
	}
}
