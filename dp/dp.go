// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package dp

// DataProtectionProvider creates a protector for a caller-supplied purpose.
// input: purpose string -> behavior: derive scoped protector -> output: protector.
type DataProtectionProvider interface {
	Create(string) DataProtector
}

// DataProtector protects and restores opaque byte payloads.
// input: bytes -> behavior: encode/decode without external side effects -> output: bytes or error.
type DataProtector interface {
	Protect([]byte) []byte
	Unprotect([]byte) ([]byte, error)
}

