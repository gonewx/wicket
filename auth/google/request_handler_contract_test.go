// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package google_test

import (
	"github.com/gonewx/wicket/auth"
	"github.com/gonewx/wicket/auth/google"
)

// The callback dispatch middleware drives external identity providers through the
// RequestHandler contract. google.Handler acquires ShouldHandleRequest and
// HandleRequest by embedding the remote handler; this compile-time assertion
// guards that the promotion keeps satisfying the contract as the type evolves.
var _ auth.RequestHandler = (*google.Handler)(nil)
