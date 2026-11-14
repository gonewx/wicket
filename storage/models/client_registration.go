// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package models

import "time"

// ClientRegistration is the record a storage.ClientRegistrationStore keeps for
// one registered client. Its client id is Client.ClientId; the record carries
// no issuer field because a store serves a single issuer.
type ClientRegistration struct {
	// Client is the registered client. An adapter persists it as the opaque
	// bytes of storage.EncodeClient and restores it with storage.DecodeClient.
	Client *Client
	// Revision is the stored revision of the record. The store assigns it: a
	// registration commits revision 1 and every successful update commits the
	// expected revision plus one. A write ignores the value passed in.
	Revision int
	// RegistrationAccessTokenDigest is the digest of the registration access
	// token issued for the client. The store keeps it as given and offers no
	// lookup by it.
	RegistrationAccessTokenDigest string
	// RegistrationTime is when the client was registered.
	RegistrationTime time.Time
}
