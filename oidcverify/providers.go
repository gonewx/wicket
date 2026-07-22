// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package oidcverify

import "time"

const (
	AppleIssuer  = "https://appleid.apple.com"
	AppleJWKSURI = "https://appleid.apple.com/auth/keys"

	GoogleIssuerHTTPS = "https://accounts.google.com"
	GoogleIssuerPlain = "accounts.google.com"
	GoogleJWKSURI     = "https://www.googleapis.com/oauth2/v3/certs"
)

func AppleConfig(audience string) ProviderConfig {
	return ProviderConfig{
		Issuers:   []string{AppleIssuer},
		JWKSURI:   AppleJWKSURI,
		Audiences: []string{audience},
		ClockSkew: 5 * time.Minute,
	}
}

func GoogleConfig(audiences ...string) ProviderConfig {
	return ProviderConfig{
		Issuers:   []string{GoogleIssuerHTTPS, GoogleIssuerPlain},
		JWKSURI:   GoogleJWKSURI,
		Audiences: audiences,
		ClockSkew: 5 * time.Minute,
	}
}
