// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package di

// SetRevokeGrantsOnSessionSubjectChange declares whether the grants issued
// within a browser session are revoked once a different user signs in on
// that session: its authorization codes, refresh tokens, reference tokens and
// persisted grants. Grants of other sessions are kept, and a failed
// revocation is logged without failing the sign-in. It requires server-side
// sessions; without them it does nothing. Refresh tokens record their
// session only while this is declared, so a refresh token issued before is
// not revoked. While declared, the same user signing in again continues the
// session the session cookie names, when its record exists and has not
// expired, instead of starting a new one: the session id is kept and the
// record is renewed through the session store, and a failed renewal fails
// the sign-in. Off by default. It must be called before Freeze.
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
