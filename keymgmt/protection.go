// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package keymgmt

import (
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
// protection seam. A nil provider means protection is unavailable, so no key may
// be created or signed with.
type keyProtector struct {
	protector dp.DataProtector
}

func newKeyProtector(provider dp.DataProtectionProvider) *keyProtector {
	if provider == nil {
		return &keyProtector{}
	}
	return &keyProtector{protector: provider.Create(protectionPurpose)}
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
