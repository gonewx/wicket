// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package common

import "time"

type StubClock struct {
	NowFunc func() time.Time
}

func NewStubClock() *StubClock {
	return &StubClock{
		NowFunc: time.Now,
	}
}

func (c *StubClock) Now() time.Time {
	return c.NowFunc()
}
