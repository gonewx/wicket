// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package mock

import (
	"context"

	"github.com/gonewx/wicket/models/messages"
	"github.com/google/uuid"
)

type MockMessageStore[T any] struct {
	Ids      []string
	Messages []*messages.Message[*T]
}

func NewMockMessageStore[T any]() *MockMessageStore[T] {
	return &MockMessageStore[T]{
		Messages: make([]*messages.Message[*T], 0),
		Ids:      make([]string, 0),
	}
}

func (s *MockMessageStore[T]) Write(ctx context.Context, message *messages.Message[*T]) (string, error) {
	id := uuid.New().String()
	s.Ids = append(s.Ids, id)
	s.Messages = append(s.Messages, message)
	return id, nil
}

func (s *MockMessageStore[T]) Read(ctx context.Context, id string) (*messages.Message[*T], error) {
	for i, m := range s.Messages {
		if s.Ids[i] == id {
			return m, nil
		}
	}
	return nil, nil
}
