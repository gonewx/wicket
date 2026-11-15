// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package wicket

import "errors"

// DPoP (RFC 9449).
const (
	// DPoPHeaderName is the request header carrying a DPoP proof.
	DPoPHeaderName = "DPoP"
	// TokenResponseTypesDPoP is the token_type of a token response whose
	// access token is bound to a DPoP proof key. It names the token
	// response type, not one of the internal token kinds TokenTypes*.
	TokenResponseTypesDPoP = "DPoP"
	// DiscoveryDPoPSigningAlgValuesSupported is the discovery metadata name
	// listing the accepted DPoP proof signature algorithms.
	DiscoveryDPoPSigningAlgValuesSupported = "dpop_signing_alg_values_supported"
	// DPoPNonceHeaderName is the response header carrying a fresh server
	// nonce for the next DPoP proof (RFC 9449 section 8).
	DPoPNonceHeaderName = "DPoP-Nonce"
	// AuthorizeRequestDPoPJkt is the authorize request parameter naming the
	// thumbprint of the DPoP key the authorization code is bound to
	// (RFC 9449 section 10).
	AuthorizeRequestDPoPJkt = "dpop_jkt"
)

// TokenErrorsInvalidDPoPProof is the token endpoint error answering an
// invalid or replayed DPoP proof (RFC 9449 section 5).
var TokenErrorsInvalidDPoPProof = errors.New("invalid_dpop_proof")

// TokenErrorsUseDPoPNonce is the token endpoint error answering a DPoP proof
// that carries no server nonce, or one that is not accepted (RFC 9449
// section 8). The response carries a fresh nonce in DPoPNonceHeaderName.
var TokenErrorsUseDPoPNonce = errors.New("use_dpop_nonce")
