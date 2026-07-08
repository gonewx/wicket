// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package keymgmt

import (
	"bytes"
	"encoding/base64"
	"fmt"

	"github.com/gonewx/wicket/dp"
)

// protectionFormatV1 tags private material protected by the current scheme. It
// is written into Record.Format and lets a later scheme coexist with records
// written under this one.
const protectionFormatV1 = "keymgmt.protected.v1"

// protectionPurpose scopes the derived data protector.
const protectionPurpose = "keymgmt.key-material"

// keyProtector protects and recovers private key material through the host data
// protection seam. A nil provider, or a protector that fails the construction
// probe, means protection is unavailable, so no key may be created or signed
// with.
type keyProtector struct {
	protector dp.DataProtector
}

func newKeyProtector(provider dp.DataProtectionProvider) *keyProtector {
	if provider == nil {
		return &keyProtector{}
	}
	protector := provider.Create(protectionPurpose)
	if protector == nil || !probeProtector(protector) {
		return &keyProtector{}
	}
	return &keyProtector{protector: protector}
}

// probeProtector proves the protector actually transforms its input and can
// recover it. An identity transform would persist private material effectively
// in the clear while the record claims it is protected, and a protector that
// cannot round-trip would strand every key it wrote — both are treated as
// unavailable so key creation fails closed instead.
func probeProtector(p dp.DataProtector) bool {
	probe := []byte("keymgmt.protection.probe")
	sealed := p.Protect(probe)
	if bytes.Equal(sealed, probe) {
		return false
	}
	recovered, err := p.Unprotect(sealed)
	return err == nil && bytes.Equal(recovered, probe)
}

func (p *keyProtector) available() bool {
	return p != nil && p.protector != nil
}

// protect wraps plaintext private material and reports the format tag written
// alongside it.
func (p *keyProtector) protect(private []byte) ([]byte, string, error) {
	if !p.available() {
		return nil, "", ErrProtectorUnavailable
	}
	return p.protector.Protect(private), protectionFormatV1, nil
}

// recover restores plaintext private material previously protected under format.
func (p *keyProtector) recover(protected []byte, format string) ([]byte, error) {
	if !p.available() {
		return nil, ErrProtectorUnavailable
	}
	if format != protectionFormatV1 {
		return nil, fmt.Errorf("%w: unknown protection format %q", ErrConfiguration, format)
	}
	plain, err := p.protector.Unprotect(protected)
	if err != nil {
		return nil, fmt.Errorf("unprotect private key: %w", err)
	}
	return plain, nil
}

func base64URL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}
