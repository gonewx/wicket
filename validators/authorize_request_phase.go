// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package validators

// AuthorizeRequestPhase is the point of the authorization flow at which the
// caller asks for an authorize request to be validated. The caller declares
// it; the validator never infers it from the endpoint.
type AuthorizeRequestPhase int

const (
	// AuthorizeRequestPhaseEntry is the first arrival of the request at the
	// authorize endpoint. It is the zero value.
	AuthorizeRequestPhaseEntry AuthorizeRequestPhase = iota
	// AuthorizeRequestPhaseInteractionReturn is the return of the request
	// from an interaction page (login, consent), at the authorize callback
	// or when an interaction page parses its return URL. A pushed request
	// is judged as a round trip only when it carries a valid entry receipt;
	// otherwise it is judged as an entry.
	AuthorizeRequestPhaseInteractionReturn
	// AuthorizeRequestPhasePush is the validation of the parameters of a
	// pushed authorization request at the pushed authorization request
	// endpoint.
	AuthorizeRequestPhasePush
)
