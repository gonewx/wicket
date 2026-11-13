// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package wicket

type Option[T any] func(*T)

type Identity interface {
	IsAuthenticated() bool
	AuthenticationType() string
	Name() string
}

type Principal interface {
	Identity() Identity
}
