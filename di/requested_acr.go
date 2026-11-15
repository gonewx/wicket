// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package di

// RequireRequestedAcr declares that an authorize request listing acr_values
// is answered only once the session's acr claim is one of them. A session
// that does not satisfy the request is sent to the login page once; when the
// returning session still does not satisfy it, or the request carries
// prompt=none, the client receives unmet_authentication_requirements. It must
// be called before Freeze. A repeated call has no further effect.
func (c *ServerConfig) RequireRequestedAcr() {
	if c.frozen {
		panic("RequireRequestedAcr must not be called after Freeze")
	}
	c.requestedAcrRequired = true
}

// RequestedAcrRequired reports whether the requested acr_values were declared
// to be enforced.
func (c *ServerConfig) RequestedAcrRequired() bool {
	return c != nil && c.requestedAcrRequired
}
