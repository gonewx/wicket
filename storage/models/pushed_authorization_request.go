// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package models

import "time"

// PushedAuthorizationRequest is one pushed authorization request (RFC 9126)
// as the store keeps it. The authorization parameters travel in Payload as
// opaque protected bytes; the store never sees them in the clear and never
// sees the request_uri handed to the client, only the key derived from it.
type PushedAuthorizationRequest struct {
	// ClientId is the client that pushed the request. It is a visible field
	// so adapters can index it.
	ClientId string

	// CreationTime is when the request was pushed.
	CreationTime time.Time

	// EntryExpiration ends the validity of the request_uri as an entry
	// point: an authorization request presenting the handle after this
	// instant is rejected by the core. It does not drive reclamation.
	EntryExpiration time.Time

	// RetentionExpiration is EntryExpiration plus the grace the interaction
	// round trip needs (login, consent) after the handle was presented. The
	// record must stay readable until then; RemoveExpired reclaims on this
	// field only.
	RetentionExpiration time.Time

	// Payload is the protected authorization parameters, produced by
	// storage.ProtectPushedAuthorizationParameters. Stores treat it as
	// opaque bytes.
	Payload []byte
}
