// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package di

import (
	"errors"
	"fmt"

	"github.com/gonewx/wicket/dpop"
)

// The DPoP nonce key seam provides the keys of server nonces (RFC 9449
// section 8). It is feature-required while DPoP is enabled with
// RequireNonce, and it has no fallback of any kind: AllowInMemoryFallback
// does not exempt it and no per-seam fallback declaration exists. It is
// unrelated to dp.DataProtectionProvider and is not registered in the
// container; while nonces are not required, no code path reads it.

// dpopNonceKeySeamName is the seam name as failures report it.
const dpopNonceKeySeamName = "dpop nonce key"

// SetDPoPNonceKeys installs the source of the keys that authenticate DPoP
// server nonces. Every replica has to be given the same keys. A repeated
// call replaces the source; a nil source stands for none. It must be called
// before Freeze.
func (c *ServerConfig) SetDPoPNonceKeys(source dpop.NonceKeySource) {
	if c.frozen {
		panic("SetDPoPNonceKeys must not be called after Freeze")
	}
	c.dpopNonceKeys = source
}

// dpopNonceRequired reports whether DPoP is enabled with RequireNonce, which
// is the condition of the nonce key seam.
func (c *ServerConfig) dpopNonceRequired() bool {
	return c != nil && c.DPoPEnabled() && c.dpopOptions.RequireNonce
}

// dpopNonceKeysForFeature returns the nonce key source to the enabled
// feature. It fails while nonces are not required and when the host
// injected no source.
func (c *ServerConfig) dpopNonceKeysForFeature() (dpop.NonceKeySource, error) {
	if !c.dpopNonceRequired() {
		return nil, fmt.Errorf("store seam %q used although DPoP server nonces are not required", dpopNonceKeySeamName)
	}
	if c.dpopNonceKeys == nil {
		return nil, fmt.Errorf("store seam %q not injected by host", dpopNonceKeySeamName)
	}
	return c.dpopNonceKeys, nil
}

// requireDPoPNonceKeySeam panics when nonces are required and the injected
// source fails to provide keys or provides keys that do not validate. A
// missing source is reported by the store seam validation. The source is
// not read while nonces are not required.
func (c *ServerConfig) requireDPoPNonceKeySeam() {
	if !c.dpopNonceRequired() || c.dpopNonceKeys == nil {
		return
	}
	current, previous, err := c.dpopNonceKeys.NonceKeys()
	if err == nil {
		err = dpop.ValidateNonceKeys(current, previous)
	}
	if err != nil {
		panic(fmt.Sprintf("store seam %q injected by host provides no usable keys: %v", dpopNonceKeySeamName, err))
	}
}

// failingNonceKeys is the source of an assembly whose nonce key seam could
// not be read: every read fails, so every request carrying a proof is
// answered with a server error instead of being served without nonces.
type failingNonceKeys struct{ err error }

func (s failingNonceKeys) NonceKeys() (dpop.NonceKey, []dpop.NonceKey, error) {
	if s.err == nil {
		return dpop.NonceKey{}, nil, errors.New("dpop nonce keys unavailable")
	}
	return dpop.NonceKey{}, nil, s.err
}
