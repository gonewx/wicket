// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"encoding/base64"

	"github.com/gonewx/wicket/dp"
)

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

// Protect encodes the payload as base64url so the protected form is safe to
// carry in cookies and URLs, matching what consumers expect from a protected
// payload. It provides transport-safe encoding, not confidentiality.
func (p dataProtector) Create(purpose string) dp.DataProtector {
	return dataProtector{purpose: p.purpose + "." + purpose}
}

func (p dataProtector) Protect(data []byte) []byte {
	out := make([]byte, base64.RawURLEncoding.EncodedLen(len(data)))
	base64.RawURLEncoding.Encode(out, data)
	return out
}

func (p dataProtector) Unprotect(data []byte) ([]byte, error) {
	out := make([]byte, base64.RawURLEncoding.DecodedLen(len(data)))
	n, err := base64.RawURLEncoding.Decode(out, data)
	if err != nil {
		return nil, err
	}
	return out[:n], nil
}
