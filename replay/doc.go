// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

// Package replay declares the port that makes a one-time identifier usable
// once: a registry that accepts a key the first time it is offered and
// refuses it on every later attempt, until the host reclaims it. The core
// uses it for the jti of a client assertion and of a DPoP proof, so a
// captured credential cannot be presented a second time within its validity
// window — also when several replicas share one registry.
//
// # The port
//
// Registry has two operations and nothing else. Register records a key
// together with the instant its record may be reclaimed; it is insert-only
// and atomic, so of any number of concurrent calls for one key exactly one
// succeeds and every other call reports ErrDuplicateHandle. RemoveExpired is
// the only way a record leaves the registry: the caller passes an instant and
// the registry drops every record that expires strictly before it. There is
// no lookup, no removal by key and no enumeration, which leaves a caller no
// way to check first and write afterwards.
//
// A registry never consults a clock. Whether a record is past its expiry
// plays no part in the duplicate decision: a key that was registered and not
// yet reclaimed is a duplicate. Deciding the expiry instant is the caller's
// job, and reclaiming is the host's.
//
// A caller sorts the result of Register three ways: nil means first use,
// an error matching ErrDuplicateHandle means replay, and any other error is
// an infrastructure failure that neither proves a replay nor permits the
// request.
//
// # Keys
//
// Key is the only function that produces a registry key. It takes a Purpose
// (client assertion or DPoP proof), a qualifier (the client id, or the proof
// key thumbprint) and the jti, encodes the three without ambiguity and
// returns the lowercase hexadecimal SHA-256 digest. A registry therefore
// stores neither the jti nor the qualifier, and keys of the two purposes
// never collide.
//
// # Implementations
//
// MemoryRegistry keeps the records in process memory. It suits development
// and single-process hosts; replicas do not share it. Adapters for shared
// media live outside this repository and prove themselves against the suite
// in package replaytest.
package replay
