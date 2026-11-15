// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package models

import "net/url"

// PushedAuthorizationRequestValues carries the pushed authorization request
// (RFC 9126) a validated authorize request was expanded from. Both fields are
// empty for a request that did not present a pushed request_uri.
type PushedAuthorizationRequestValues struct {
	// PushedRequestUri is the request_uri the request presented.
	PushedRequestUri string
	// PushedParameters are the authorization parameters the request was
	// validated with: the pushed parameters, after any request object was
	// applied. On a validated interaction round trip they also hold the
	// server's internal suppressed prompt marker (wicket.SuppressedPrompt),
	// which is no authorization parameter. Raw then holds only client_id, request_uri and the entry
	// receipt, so the expanded parameters never travel through the browser.
	PushedParameters url.Values
}
