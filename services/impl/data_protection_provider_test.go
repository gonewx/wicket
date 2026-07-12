// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"bytes"
	"testing"
)

// TestDataProtectorRoundTripIsTransportSafe verifies the protected form is
// cookie/URL-safe and restores the original payload exactly.
func TestDataProtectorRoundTripIsTransportSafe(t *testing.T) {
	t.Parallel()

	p := NewDataProtectionProvider().Create("purpose")
	payload := []byte(`{"Created":1,"Data":{"a":"b c/d?e=f"}}`)

	protected := p.Protect(payload)
	for _, b := range protected {
		if b == '"' || b == ';' || b == ',' || b == ' ' || b == '=' || b == '&' {
			t.Fatalf("protected form contains a transport-unsafe byte %q", b)
		}
	}

	restored, err := p.Unprotect(protected)
	if err != nil {
		t.Fatalf("unprotect: %v", err)
	}
	if !bytes.Equal(restored, payload) {
		t.Fatalf("round trip = %q, want %q", restored, payload)
	}
}

// TestDataProtectorUnprotectRejectsMalformedInput verifies tampered input
// surfaces an error instead of garbage.
func TestDataProtectorUnprotectRejectsMalformedInput(t *testing.T) {
	t.Parallel()

	p := NewDataProtectionProvider().Create("purpose")
	if _, err := p.Unprotect([]byte("%%not-base64%%")); err == nil {
		t.Fatalf("Unprotect accepted malformed input")
	}
}
