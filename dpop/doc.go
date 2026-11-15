// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

// Package dpop verifies DPoP proofs (RFC 9449) presented at the token
// endpoint and carries the proof key thumbprint to the code that binds the
// issued tokens.
//
// A proof is checked in two steps. Verifier.Verify runs every check that
// changes no state: the structure of the compact JWS, its protected header,
// the signature made with the public key the header carries, and the claims
// jti, htm, htu and iat. Register then records the proof identifier with the
// replay registry, under a key qualified by the proof key thumbprint. A
// caller runs Register only after every stateless check of the request
// passed.
//
// The thumbprint of an accepted proof travels down the request context
// (WithProof, ProofThumbprint). AccessTokenBinder turns it into the jkt
// confirmation of the access token.
package dpop
