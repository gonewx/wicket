// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package di

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/gonewx/wicket/replay"
)

// The replay registry seam is required only while a feature that depends on
// it is enabled. Unlike the store seams listed by storeSeams it is not
// covered by AllowInMemoryFallback: a per-process registry gives no replay
// protection across replicas, so a host has to accept it for this seam by
// name through AllowInMemoryReplayRegistryFallback.

// replayRegistrySeamName is how the seam is named in failures and warnings.
const replayRegistrySeamName = "replay registry"

// SetReplayRegistryProvider installs the provider of the host's replay
// registry. The provider is not called before the registry is first used.
func (c *ServerConfig) SetReplayRegistryProvider(provider func() replay.Registry) {
	c.replayRegistryProvider = provider
}

// SetReplayRegistry installs the host's replay registry.
func (c *ServerConfig) SetReplayRegistry(registry replay.Registry) {
	c.SetReplayRegistryProvider(func() replay.Registry { return registry })
}

// ReplayRegistry returns the replay registry the host provided, or nil when
// it provided none.
func (c *ServerConfig) ReplayRegistry() replay.Registry {
	if c == nil || c.replayRegistryProvider == nil {
		return nil
	}
	return c.replayRegistryProvider()
}

// AllowInMemoryReplayRegistryFallback declares that the host accepts the
// in-memory replay registry when it injects none. The in-memory registry is
// correct within a single process only. AllowInMemoryFallback does not imply
// this declaration.
func (c *ServerConfig) AllowInMemoryReplayRegistryFallback() {
	c.allowInMemoryReplayRegistryFallback = true
}

// enableReplayDependentFeature records that a feature depending on the replay
// registry is enabled: "private_key_jwt" or "dpop". The record keeps
// first-enabled order and holds each name once; the seam is required exactly
// when the record is non-empty.
func (c *ServerConfig) enableReplayDependentFeature(name string) {
	if c.replayDependentFeatureEnabled(name) {
		return
	}
	c.replayDependentFeatures = append(c.replayDependentFeatures, name)
}

// replayDependentFeatureEnabled reports whether the named feature was
// recorded by enableReplayDependentFeature.
func (c *ServerConfig) replayDependentFeatureEnabled(name string) bool {
	if c == nil {
		return false
	}
	for _, enabled := range c.replayDependentFeatures {
		if enabled == name {
			return true
		}
	}
	return false
}

// requireReplayRegistrySeam is the assembly-time check Freeze runs for the
// replay registry seam. It does nothing while no dependent feature is
// enabled, and it never calls the provider.
func (c *ServerConfig) requireReplayRegistrySeam() {
	if len(c.replayDependentFeatures) == 0 {
		return
	}
	if c.replayRegistryProvider != nil || c.allowInMemoryReplayRegistryFallback {
		return
	}
	panic(fmt.Sprintf(
		"store seam %q is required by enabled features [%s] but was not injected by host; AllowInMemoryFallback does not cover it, inject a registry or call AllowInMemoryReplayRegistryFallback",
		replayRegistrySeamName, strings.Join(c.replayDependentFeatures, ", "),
	))
}

// lazyReplayRegistry defers reading the replay registry seam until the first
// Register or RemoveExpired call.
type lazyReplayRegistry struct {
	cfg    *ServerConfig
	logger *slog.Logger
	once   sync.Once
	impl   replay.Registry
	// failure is why the seam could not be materialized. It is set once and
	// every call panics with it while impl is nil.
	failure string
}

var _ replay.Registry = (*lazyReplayRegistry)(nil)
var _ io.Closer = (*lazyReplayRegistry)(nil)

// NewlazyReplayRegistry returns the lazy wrapper for the replay registry
// seam. The name follows the "New" + type name convention described in
// lifecycle.go. Nothing registers the wrapper with the container yet.
func NewlazyReplayRegistry(cfg *ServerConfig, logger *slog.Logger) *lazyReplayRegistry {
	return &lazyReplayRegistry{cfg: cfg, logger: logger}
}

// materialize resolves the seam once. It records a failure instead of
// panicking so that registry can repeat the same failure on every call.
func (r *lazyReplayRegistry) materialize() {
	if r.cfg == nil || len(r.cfg.replayDependentFeatures) == 0 {
		r.failure = fmt.Sprintf("store seam %q used although no feature that depends on it is enabled", replayRegistrySeamName)
		return
	}
	// Stands if the host's provider panics: later calls then fail with this
	// text instead of an empty one.
	r.failure = fmt.Sprintf("store seam %q could not be read from the host's provider", replayRegistrySeamName)
	if impl := r.cfg.ReplayRegistry(); impl != nil {
		r.impl = impl
		return
	}
	if !r.cfg.allowInMemoryReplayRegistryFallback {
		r.failure = fmt.Sprintf("store seam %q not injected by host and AllowInMemoryReplayRegistryFallback not declared", replayRegistrySeamName)
		return
	}
	warnFallback(r.logger, replayRegistrySeamName)
	r.impl = replay.NewMemoryRegistry()
}

func (r *lazyReplayRegistry) registry() replay.Registry {
	r.once.Do(r.materialize)
	if r.impl == nil {
		panic(r.failure)
	}
	return r.impl
}

func (r *lazyReplayRegistry) Register(ctx context.Context, key string, expiresAt time.Time) error {
	return r.registry().Register(ctx, key, expiresAt)
}

func (r *lazyReplayRegistry) RemoveExpired(ctx context.Context, cutoff time.Time) (int, error) {
	return r.registry().RemoveExpired(ctx, cutoff)
}

// Close releases a materialized host adapter, if any. See the package
// lifecycle contract. A wrapper that was never used, or whose seam could not
// be materialized, releases nothing.
func (r *lazyReplayRegistry) Close() error {
	return closeMaterialized(r.impl)
}
