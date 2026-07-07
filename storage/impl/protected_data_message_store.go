// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/gonewx/wicket/dp"
	"github.com/gonewx/wicket/models/messages"
)

const (
	ProtectedDataMessageStorePurpose = "gois.Stores.ProtectedDataMessageStore"
)

// MessageStore Interface for a message store
type ProtectedDataMessageStore[T any] struct {
	Protector dp.DataProtector
	Logger    *slog.Logger
}

func NewProtectedDataMessageStore[T any](
	provider dp.DataProtectionProvider,
	logger *slog.Logger,
) *ProtectedDataMessageStore[T] {
	return &ProtectedDataMessageStore[T]{
		Protector: provider.Create(ProtectedDataMessageStorePurpose),
		Logger:    logger,
	}
}

// Writes the message.
// return An identifier for the message
func (s *ProtectedDataMessageStore[T]) Write(message *messages.Message[*T]) (string, error) {
	b, err := json.Marshal(message)
	if err != nil {
		s.Logger.Error("Exception writing protected message", slog.String("err", err.Error()))
		return "", fmt.Errorf("Exception writing protected message: %w", err)
	}

	b = s.Protector.Protect(b)

	return base64.URLEncoding.EncodeToString(b), nil
}

// Reads the message.
func (s *ProtectedDataMessageStore[T]) Read(value string) (*messages.Message[*T], error) {
	var message messages.Message[*T]

	if strings.TrimSpace(value) == "" {
		return nil, nil

	}

	b, err := base64.URLEncoding.DecodeString(value)
	if err != nil {
		s.Logger.Error("Exception reading protected message", slog.String("err", err.Error()))
		return nil, fmt.Errorf("Exception reading protected message: %w", err)
	}

	b, err = s.Protector.Unprotect(b)
	if err != nil {
		s.Logger.Error("Exception unprotected message", slog.String("err", err.Error()))
		return nil, err
	}

	err = json.Unmarshal(b, &message)
	if err != nil {
		s.Logger.Error("Exception reading protected message", slog.String("err", err.Error()))
		return nil, fmt.Errorf("Exception reading protected message: %w", err)
	}

	return &message, nil

}
