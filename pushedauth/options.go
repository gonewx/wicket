// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

// Package pushedauth implements pushed authorization requests (RFC 9126):
// storing the parameters a client pushes, resolving the request_uri an
// authorization request presents, and consuming it once the authorize
// endpoint answers the client.
package pushedauth

import (
	"fmt"
	"time"
)

// Default durations of Options.
const (
	// DefaultRequestUriLifetime is the default entry lifetime of a
	// request_uri, the expires_in of the push response.
	DefaultRequestUriLifetime = 60 * time.Second
	// DefaultInteractionGracePeriod is the default time a pushed request
	// stays usable after its entry lifetime, for an interaction round trip
	// (login, consent) that started in time.
	DefaultInteractionGracePeriod = 10 * time.Minute
)

// Clock tells the current time.
type Clock interface {
	Now() time.Time
}

// Options configure pushed authorization requests.
type Options struct {
	// RequestUriLifetime is the entry lifetime of a request_uri: an
	// authorization request presenting it for the first time after this
	// long is rejected. Zero means DefaultRequestUriLifetime. A client's
	// own RequestUriLifetime takes precedence.
	RequestUriLifetime time.Duration
	// InteractionGracePeriod extends the life of a pushed request beyond its
	// entry lifetime for an interaction round trip that entered in time.
	// Zero means DefaultInteractionGracePeriod.
	InteractionGracePeriod time.Duration
	// RequireForAllClients makes the authorize endpoint accept requests of
	// every client only through a pushed request_uri.
	RequireForAllClients bool
	// Clock tells the time. Nil means the server's system clock.
	Clock Clock
}

// Validate reports an error for a negative duration.
func (o Options) Validate() error {
	if o.RequestUriLifetime < 0 {
		return fmt.Errorf("pushedauth: negative RequestUriLifetime %s", o.RequestUriLifetime)
	}
	if o.InteractionGracePeriod < 0 {
		return fmt.Errorf("pushedauth: negative InteractionGracePeriod %s", o.InteractionGracePeriod)
	}
	return nil
}

// WithDefaults returns a copy of o with every zero duration replaced by its
// default. The clock is left as it is.
func (o Options) WithDefaults() Options {
	if o.RequestUriLifetime == 0 {
		o.RequestUriLifetime = DefaultRequestUriLifetime
	}
	if o.InteractionGracePeriod == 0 {
		o.InteractionGracePeriod = DefaultInteractionGracePeriod
	}
	return o
}
