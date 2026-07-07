// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package gois

type Decorator[T any] struct {
	Instance T
}

func NewDecorator[T any](instance T) *Decorator[T] {
	return &Decorator[T]{
		Instance: instance,
	}
}
