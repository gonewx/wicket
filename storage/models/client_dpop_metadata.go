// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package models

// ClientDPoPMetadata is the DPoP (RFC 9449) metadata a client registers. The
// zero value means the client may, but need not, present DPoP proofs.
type ClientDPoPMetadata struct {
	// RequireDPoP makes the token endpoint refuse the client's token requests
	// that carry no DPoP proof. It corresponds to the dpop_bound_access_tokens
	// client metadata of RFC 9449 section 5.2. It is valid only while DPoP is
	// enabled and the client does not receive access tokens via the browser.
	RequireDPoP bool
}
