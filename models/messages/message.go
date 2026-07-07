// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package messages

type Message[T any] struct {
	Created int64
	Data    T
}

func NewMessage[T any](data T) *Message[T] {
	return &Message[T]{Data: data}
}

func NewMessageWithCreated[T any](data T, created int64) *Message[T] {
	return &Message[T]{Data: data, Created: created}
}
