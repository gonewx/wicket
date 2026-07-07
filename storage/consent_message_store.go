// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package storage

import "github.com/gonewx/wicket/models/messages"

// ConsentMessageStore Interface for a message store
type ConsentMessageStore interface {
	// Writes the consent response message.
	// return An identifier for the message
	Write(id string, message *messages.Message[*messages.ConsentResponse]) error

	// Reads the message.
	Read(id string) (*messages.Message[*messages.ConsentResponse], error)

	// Deletes the consent response message.
	Delete(id string) error
}
