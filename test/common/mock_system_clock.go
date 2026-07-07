// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package common

import "time"

type MockSystemClock struct {
	now time.Time
}

func NewMockSystemClock() *MockSystemClock {
	return &MockSystemClock{}
}

func (m *MockSystemClock) SetNow(now time.Time) {
	m.now = now
}

func (m *MockSystemClock) Now() time.Time {
	return m.now
}
