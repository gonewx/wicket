// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package di

import (
	"fmt"

	"github.com/gonewx/wicket/dp"
)

// SessionCookieProtectionPurpose is the purpose the session cookie protector
// is created with from the provider injected through
// SetSessionCookieDataProtectionProvider.
const SessionCookieProtectionPurpose = "wicket.session-cookie"

// sessionCookieDataProtectionSeamName names the session cookie data
// protection seam as failures report it.
const sessionCookieDataProtectionSeamName = "session cookie data protection"

// SetRevokeGrantsOnSessionSubjectChange declares whether the grants issued
// within a browser session are revoked once a different user signs in on
// that session: its authorization codes, refresh tokens, reference tokens and
// persisted grants. Grants of other sessions are kept, and a failed
// revocation is logged without failing the sign-in. It requires server-side
// sessions; without them it does nothing at request time. Refresh tokens
// record their session only while this is declared, so a refresh token
// issued before is not revoked. While declared, the same user signing in
// again continues the session the session cookie names, when its record
// exists and has not expired, instead of starting a new one: the session id
// is kept and the record is renewed through the session store, and a failed
// renewal fails the sign-in. While declared, the session cookie carries the
// session id protected with the provider injected through
// SetSessionCookieDataProtectionProvider, which Freeze then requires whether
// or not server-side sessions are enabled. Off by default. It must be called
// before Freeze.
func (c *ServerConfig) SetRevokeGrantsOnSessionSubjectChange(revoke bool) {
	if c.frozen {
		panic("SetRevokeGrantsOnSessionSubjectChange must not be called after Freeze")
	}
	c.sessionGrantRevocation = revoke
}

// RevokeGrantsOnSessionSubjectChange reports whether the grants of a browser
// session are revoked once a different user signs in on it.
func (c *ServerConfig) RevokeGrantsOnSessionSubjectChange() bool {
	if c == nil {
		return false
	}
	return c.sessionGrantRevocation
}

// SetSessionCookieDataProtectionProvider installs the data protection
// provider applied to the session cookie while
// SetRevokeGrantsOnSessionSubjectChange is declared, and to nothing else.
// The cookie then carries the session id protected with a protector created
// for SessionCookieProtectionPurpose, so that a session id relying parties
// learn as sid cannot be turned into a session cookie. It is required while
// the revocation is declared and must not be the default
// services/impl.DataProtectionProvider, which only encodes: Freeze rejects
// it whether or not the revocation is declared. The container's
// dp.DataProtectionProvider binding is unaffected. The provider must
// authenticate what it protects (an AEAD or a MAC, not an encoding only) and
// keep the protectors it creates for different purposes apart; otherwise a
// session cookie can be forged, or a value protected for another purpose
// passes for one. It must be called before Freeze.
func (c *ServerConfig) SetSessionCookieDataProtectionProvider(provider dp.DataProtectionProvider) {
	if c.frozen {
		panic("SetSessionCookieDataProtectionProvider must not be called after Freeze")
	}
	c.sessionCookieDataProtectionProvider = provider
}

// requireSessionCookieDataProtectionSeam rejects the default data protection
// implementation on the session cookie seam whether or not the revocation is
// declared, and a missing provider while it is declared.
func (c *ServerConfig) requireSessionCookieDataProtectionSeam() {
	provider := c.sessionCookieDataProtectionProvider
	if provider != nil && isDefaultDataProtectionProvider(provider) {
		panic(fmt.Sprintf("store seam %q injected by host through SetSessionCookieDataProtectionProvider with the default %T, which only encodes; inject a provider that protects the session cookie", sessionCookieDataProtectionSeamName, provider))
	}
	if provider == nil && c.RevokeGrantsOnSessionSubjectChange() {
		panic(fmt.Sprintf("store seam %q is required by SetRevokeGrantsOnSessionSubjectChange and not injected by host; call SetSessionCookieDataProtectionProvider", sessionCookieDataProtectionSeamName))
	}
}

// sessionCookieProtectorForFeature returns the session cookie protector,
// created from the host's provider with SessionCookieProtectionPurpose. It
// fails while the revocation is not declared, when the host injected no
// provider, when the provider is the default implementation, and when it
// creates no protector.
func (c *ServerConfig) sessionCookieProtectorForFeature() (dp.DataProtector, error) {
	if !c.RevokeGrantsOnSessionSubjectChange() {
		return nil, fmt.Errorf("store seam %q used although SetRevokeGrantsOnSessionSubjectChange is not declared", sessionCookieDataProtectionSeamName)
	}
	provider := c.sessionCookieDataProtectionProvider
	if provider == nil {
		return nil, fmt.Errorf("store seam %q not injected by host; call SetSessionCookieDataProtectionProvider", sessionCookieDataProtectionSeamName)
	}
	if isDefaultDataProtectionProvider(provider) {
		return nil, fmt.Errorf("store seam %q injected through SetSessionCookieDataProtectionProvider with the default %T, which only encodes", sessionCookieDataProtectionSeamName, provider)
	}
	protector := provider.Create(SessionCookieProtectionPurpose)
	if protector == nil {
		return nil, fmt.Errorf("store seam %q: provider %T injected through SetSessionCookieDataProtectionProvider created no protector", sessionCookieDataProtectionSeamName, provider)
	}
	return protector, nil
}
