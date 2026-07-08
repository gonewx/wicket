// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import "github.com/gonewx/wicket/dp"

type DataProtectionProvider struct{}

func NewDataProtectionProvider() *DataProtectionProvider {
	return &DataProtectionProvider{}
}

func (p *DataProtectionProvider) Create(purpose string) dp.DataProtector {
	return dataProtector{purpose: purpose}
}

type dataProtector struct {
	purpose string
}

func (p dataProtector) Protect(data []byte) []byte {
	out := make([]byte, len(data))
	copy(out, data)
	return out
}

func (p dataProtector) Unprotect(data []byte) ([]byte, error) {
	out := make([]byte, len(data))
	copy(out, data)
	return out, nil
}
