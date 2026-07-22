// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package oidcverify

import "errors"

var (
	ErrMalformedToken   = errors.New("oidcverify: malformed token")
	ErrInvalidAlgorithm = errors.New("oidcverify: invalid algorithm")
	ErrKeyNotFound      = errors.New("oidcverify: key not found")
	ErrInvalidSignature = errors.New("oidcverify: invalid signature")
	ErrTokenExpired     = errors.New("oidcverify: token expired")
	ErrInvalidIssuer    = errors.New("oidcverify: invalid issuer")
	ErrInvalidAudience  = errors.New("oidcverify: invalid audience")
	ErrMissingNonce     = errors.New("oidcverify: missing nonce")
	ErrInvalidNonce     = errors.New("oidcverify: invalid nonce")
)
