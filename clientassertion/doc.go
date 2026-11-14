// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

// Package clientassertion authenticates clients and API resources that
// present a signed JWT assertion (private_key_jwt) instead of a shared
// secret.
//
// A Parser recognises the assertion parameters on a request. A Verifier
// checks one assertion: structure, signing algorithm, the registered public
// key, signature and claims, and only then records the assertion identifier
// in the replay registry, so that every stateless rejection comes before the
// single state change. A KeySource supplies the registered public keys, from
// an inline JWK Set or from the pre-registered JWK Set address, which it
// fetches and caches. ClientAuthenticator and ApiAuthenticator put these
// together in front of the shared-secret validators.
//
// Every validation failure is reported the same way, as invalid_client
// without a description. A failing replay registry or client store is
// reported as ErrAuthenticationUnavailable, which is neither a replay nor a
// success.
// Assertions, signatures, assertion identifiers, registry keys and fetched
// key sets are never logged.
package clientassertion
