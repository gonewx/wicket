// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package dynamicscheme

import (
	"maps"
	"time"
)

// Provider is a runtime-registrable authentication scheme provider record. The
// Scheme field is the unique key and maps to an authentication scheme name; the
// Protocol field maps to a scheme handler type. Config carries opaque protocol
// parameters (for example an authority URL, client id, or scope list) that a
// future handler layer interprets; this package treats Config as opaque data.
type Provider struct {
	Scheme      string
	DisplayName string
	Enabled     bool
	Protocol    string
	Config      map[string]string
}

// clone returns a deep copy so stored records never share mutable state (the
// Config map in particular) with callers.
func (p *Provider) clone() *Provider {
	if p == nil {
		return nil
	}
	dup := *p
	if p.Config != nil {
		dup.Config = make(map[string]string, len(p.Config))
		maps.Copy(dup.Config, p.Config)
	}
	return &dup
}

// ProviderStore persists dynamic provider records keyed by scheme name.
// GetProvider returns (nil, nil) when a scheme is absent; AllProviders returns
// every record including individually-disabled ones; PutProvider inserts or
// replaces by scheme; DeleteProvider is a no-op when the scheme is absent. A
// server-global store has no subject or tenant dimension.
type ProviderStore interface {
	GetProvider(scheme string) (*Provider, error)
	AllProviders() ([]*Provider, error)
	PutProvider(provider *Provider) error
	DeleteProvider(scheme string) error
}

// Clock is the injected time source; the subsystem never reads time.Now()
// directly.
type Clock interface {
	Now() time.Time
}
