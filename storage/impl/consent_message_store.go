// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	infrastructure "github.com/gonewx/wicket/infrastructure"
	"github.com/gonewx/wicket/models/messages"
)

// TODO:
// ConsentMessageStore  a message store
type ConsentMessageStore struct {
	cookie *infrastructure.MessageCookie[*messages.ConsentResponse]
}

func NewConsentMessageStore(cookie *infrastructure.MessageCookie[*messages.ConsentResponse]) *ConsentMessageStore {
	return &ConsentMessageStore{cookie: cookie}
}

// Writes the consent response message.
// return An identifier for the message
func (s *ConsentMessageStore) Write(id string, message *messages.Message[*messages.ConsentResponse]) error {
	return s.cookie.Write(id, message)
}

// Reads the message.
func (s *ConsentMessageStore) Read(id string) (*messages.Message[*messages.ConsentResponse], error) {
	return s.cookie.Read(id), nil
}

// Deletes the consent response message.
func (s *ConsentMessageStore) Delete(id string) error {
	s.cookie.Clear(id)
	return nil
}
