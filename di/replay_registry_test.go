// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package di

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gonewx/wicket/replay"
	"github.com/gonewx/wicket/storage"
	storage_models "github.com/gonewx/wicket/storage/models"
)

const replayTestKey = "7e0c6a1f5d3b49287f6e5d4c3b2a19087e6d5c4b3a29180f7e6d5c4b3a291807"

var replayTestInstant = time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC)

// replayOtherSeams lists the store seams other than the replay registry, in
// the order Freeze checks them, each with its category and a way to mark it
// injected. A provider that returns nil is enough: Freeze looks at whether a
// provider was set and never calls it.
var replayOtherSeams = []struct {
	name     string
	category storeSeamCategory
	inject   func(*ServerConfig)
}{
	{"authorization parameters message store", storeSeamOptional, func(c *ServerConfig) { c.SetAuthorizationParametersMessageStore(nil) }},
	{"persisted grant store", storeSeamRequired, func(c *ServerConfig) { c.SetPersistedGrantStore(nil) }},
	{"device flow store", storeSeamRequired, func(c *ServerConfig) { c.SetDeviceFlowStore(nil) }},
	{"backchannel authentication request store", storeSeamRequired, func(c *ServerConfig) { c.SetBackchannelAuthenticationRequestStore(nil) }},
	{"authorization code store", storeSeamRequired, func(c *ServerConfig) { c.SetAuthorizationCodeStore(nil) }},
	{"refresh token store", storeSeamRequired, func(c *ServerConfig) { c.SetRefreshTokenStore(nil) }},
	{"reference token store", storeSeamRequired, func(c *ServerConfig) { c.SetReferenceTokenStore(nil) }},
	{"user consent store", storeSeamRequired, func(c *ServerConfig) { c.SetUserConsentStore(nil) }},
	{"session store", storeSeamRequired, func(c *ServerConfig) { c.SetSessionStore(nil) }},
	{"distributed cache", storeSeamRequired, func(c *ServerConfig) { c.SetDistributedCache(nil) }},
	{"key record store", storeSeamRequired, func(c *ServerConfig) { c.SetRecordStore(nil) }},
	{"client store", storeSeamOptional, func(c *ServerConfig) { c.SetClientStore(replayOriginClientStore{}) }},
}

// replayOriginClientStore is the smallest injectable client store: Freeze
// only checks that it answers origin lookups as well.
type replayOriginClientStore struct{}

func (replayOriginClientStore) FindClientById(context.Context, string) (*storage_models.Client, error) {
	return nil, storage.ErrNotFound
}

func (replayOriginClientStore) FindClientsByAllowedOrigin(context.Context, string) ([]*storage_models.Client, error) {
	return []*storage_models.Client{}, nil
}

// replayFirstRequiredSeam is the first seam Freeze fails on when nothing is
// injected.
func replayFirstRequiredSeam() string {
	for _, seam := range replayOtherSeams {
		if seam.category == storeSeamRequired {
			return seam.name
		}
	}
	return ""
}

// replayConfig returns a configuration with every other seam injected except
// the ones named, and with the given replay dependent features enabled.
func replayConfig(features []string, without ...string) *ServerConfig {
	cfg := NewServerConfig()
	for _, seam := range replayOtherSeams {
		if !slices.Contains(without, seam.name) {
			seam.inject(cfg)
		}
	}
	for _, feature := range features {
		cfg.enableReplayDependentFeature(feature)
	}
	return cfg
}

// replayPanicString runs fn and returns the string it panicked with. It
// fails the test when fn returns normally or panics with another type.
func replayPanicString(t *testing.T, fn func()) (message string) {
	t.Helper()
	defer func() {
		t.Helper()
		recovered := recover()
		if recovered == nil {
			t.Fatal("expected a panic, got none")
		}
		text, ok := recovered.(string)
		if !ok {
			t.Fatalf("panic value is %T (%v), want a string", recovered, recovered)
		}
		message = text
	}()
	fn()
	return ""
}

func replayRequireContains(t *testing.T, text string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(text, want) {
			t.Fatalf("%q does not contain %q", text, want)
		}
	}
}

// replayLogCapture is a slog handler that keeps what it is given.
type replayLogCapture struct {
	mu      sync.Mutex
	records []slog.Record
}

func (c *replayLogCapture) Enabled(context.Context, slog.Level) bool { return true }

func (c *replayLogCapture) Handle(_ context.Context, record slog.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.records = append(c.records, record)
	return nil
}

func (c *replayLogCapture) WithAttrs([]slog.Attr) slog.Handler { return c }

func (c *replayLogCapture) WithGroup(string) slog.Handler { return c }

func (c *replayLogCapture) warnings() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var messages []string
	for _, record := range c.records {
		if record.Level == slog.LevelWarn {
			messages = append(messages, record.Message)
		}
	}
	return messages
}

type replayRegisterCall struct {
	ctx       context.Context
	key       string
	expiresAt time.Time
}

type replayRemoveCall struct {
	ctx    context.Context
	cutoff time.Time
}

// replayRecordingRegistry is a host registry double: it records the calls it
// receives and answers with whatever it was told to.
type replayRecordingRegistry struct {
	registered  []replayRegisterCall
	removals    []replayRemoveCall
	registerErr error
	removed     int
	removeErr   error
}

func (r *replayRecordingRegistry) Register(ctx context.Context, key string, expiresAt time.Time) error {
	r.registered = append(r.registered, replayRegisterCall{ctx, key, expiresAt})
	return r.registerErr
}

func (r *replayRecordingRegistry) RemoveExpired(ctx context.Context, cutoff time.Time) (int, error) {
	r.removals = append(r.removals, replayRemoveCall{ctx, cutoff})
	return r.removed, r.removeErr
}

// replayClosingRegistry is a host registry double that also holds something
// to release.
type replayClosingRegistry struct {
	replayRecordingRegistry
	closed   int
	closeErr error
}

func (r *replayClosingRegistry) Close() error {
	r.closed++
	return r.closeErr
}

// replayCountingProvider installs a provider that counts its calls.
func replayCountingProvider(cfg *ServerConfig, registry replay.Registry) *int {
	calls := 0
	cfg.SetReplayRegistryProvider(func() replay.Registry {
		calls++
		return registry
	})
	return &calls
}

// A required seam that the host neither injected nor accepted the in-memory
// registry for fails assembly, and the global fallback declaration does not
// change that.
func TestReplayRegistryFreezeFailsWhenRequiredAndNotInjected(t *testing.T) {
	featureSets := [][]string{
		{"private_key_jwt"},
		{"dpop"},
		{"private_key_jwt", "dpop"},
	}
	for _, features := range featureSets {
		for _, globalFallback := range []bool{false, true} {
			name := fmt.Sprintf("%s/global fallback %t", strings.Join(features, "+"), globalFallback)
			t.Run(name, func(t *testing.T) {
				cfg := replayConfig(features)
				if globalFallback {
					cfg.AllowInMemoryFallback()
				}

				message := replayPanicString(t, cfg.Freeze)
				replayRequireContains(t, message, "replay registry", "AllowInMemoryReplayRegistryFallback")
				replayRequireContains(t, message, features...)
				if !cfg.Frozen() {
					t.Fatal("Freeze panicked before marking the configuration frozen")
				}
			})
		}
	}

	t.Run("reported ahead of the other seams", func(t *testing.T) {
		cfg := NewServerConfig()
		cfg.enableReplayDependentFeature("dpop")

		message := replayPanicString(t, cfg.Freeze)
		replayRequireContains(t, message, "replay registry", "dpop", "AllowInMemoryReplayRegistryFallback")
	})
}

// With the seam's own fallback declaration assembly passes, and the wrapper
// lands on the in-memory registry with one warning.
func TestReplayRegistryFallbackDeclarationUsesMemoryRegistryWithWarning(t *testing.T) {
	ctx := context.Background()

	t.Run("warns once and registers in memory", func(t *testing.T) {
		cfg := replayConfig([]string{"private_key_jwt"})
		cfg.AllowInMemoryReplayRegistryFallback()
		cfg.Freeze()

		logs := &replayLogCapture{}
		wrapper := NewlazyReplayRegistry(cfg, slog.New(logs))
		if got := logs.warnings(); len(got) != 0 {
			t.Fatalf("warnings before first use = %v, want none", got)
		}

		if err := wrapper.Register(ctx, replayTestKey, replayTestInstant); err != nil {
			t.Fatalf("first Register = %v, want nil", err)
		}
		if err := wrapper.Register(ctx, replayTestKey, replayTestInstant); !errors.Is(err, replay.ErrDuplicateHandle) {
			t.Fatalf("second Register = %v, want replay.ErrDuplicateHandle", err)
		}
		if removed, err := wrapper.RemoveExpired(ctx, replayTestInstant.Add(time.Second)); removed != 1 || err != nil {
			t.Fatalf("RemoveExpired = (%d, %v), want (1, nil)", removed, err)
		}

		warnings := logs.warnings()
		if len(warnings) != 1 {
			t.Fatalf("warnings = %v, want exactly one", warnings)
		}
		replayRequireContains(t, warnings[0], "replay registry", "falling back to in-memory")

		if _, ok := wrapper.impl.(*replay.MemoryRegistry); !ok {
			t.Fatalf("wrapper materialized %T, want *replay.MemoryRegistry", wrapper.impl)
		}
	})

	t.Run("first use through RemoveExpired", func(t *testing.T) {
		cfg := replayConfig([]string{"dpop"})
		cfg.AllowInMemoryReplayRegistryFallback()
		cfg.Freeze()

		logs := &replayLogCapture{}
		wrapper := NewlazyReplayRegistry(cfg, slog.New(logs))
		if removed, err := wrapper.RemoveExpired(ctx, replayTestInstant); removed != 0 || err != nil {
			t.Fatalf("RemoveExpired = (%d, %v), want (0, nil)", removed, err)
		}
		if got := logs.warnings(); len(got) != 1 {
			t.Fatalf("warnings = %v, want exactly one", got)
		}
	})

	t.Run("nil logger", func(t *testing.T) {
		cfg := replayConfig([]string{"dpop"})
		cfg.AllowInMemoryReplayRegistryFallback()
		cfg.Freeze()

		wrapper := NewlazyReplayRegistry(cfg, nil)
		if err := wrapper.Register(ctx, replayTestKey, replayTestInstant); err != nil {
			t.Fatalf("Register = %v, want nil", err)
		}
	})

	t.Run("both fallback declarations and nothing injected", func(t *testing.T) {
		cfg := NewServerConfig()
		cfg.enableReplayDependentFeature("private_key_jwt")
		cfg.AllowInMemoryFallback()
		cfg.AllowInMemoryReplayRegistryFallback()
		cfg.Freeze()
	})
}

// An injected registry is used as it is: calls and results pass through
// untouched and nothing is logged.
func TestReplayRegistryInjectedRegistryIsUsedWithoutWarning(t *testing.T) {
	type ctxKey struct{}
	ctx := context.WithValue(context.Background(), ctxKey{}, "request")
	hostFailure := errors.New("host registry unavailable")

	for _, alsoFallback := range []bool{false, true} {
		t.Run(fmt.Sprintf("fallback declared %t", alsoFallback), func(t *testing.T) {
			host := &replayRecordingRegistry{}
			cfg := replayConfig([]string{"private_key_jwt", "dpop"})
			cfg.SetReplayRegistry(host)
			if alsoFallback {
				cfg.AllowInMemoryReplayRegistryFallback()
			}
			cfg.Freeze()

			logs := &replayLogCapture{}
			wrapper := NewlazyReplayRegistry(cfg, slog.New(logs))

			if err := wrapper.Register(ctx, replayTestKey, replayTestInstant); err != nil {
				t.Fatalf("Register = %v, want nil", err)
			}
			host.registerErr = replay.ErrDuplicateHandle
			if err := wrapper.Register(ctx, replayTestKey, replayTestInstant); err != replay.ErrDuplicateHandle {
				t.Fatalf("Register = %v, want the host's replay.ErrDuplicateHandle unchanged", err)
			}
			host.registerErr = hostFailure
			if err := wrapper.Register(ctx, replayTestKey, replayTestInstant); err != hostFailure {
				t.Fatalf("Register = %v, want the host's error unchanged", err)
			}
			if len(host.registered) != 3 {
				t.Fatalf("host received %d Register calls, want 3", len(host.registered))
			}
			for i, call := range host.registered {
				if call.ctx != ctx || call.key != replayTestKey || !call.expiresAt.Equal(replayTestInstant) {
					t.Fatalf("Register call %d reached the host with changed arguments: %+v", i, call)
				}
			}

			host.removed, host.removeErr = 7, hostFailure
			cutoff := replayTestInstant.Add(time.Minute)
			removed, err := wrapper.RemoveExpired(ctx, cutoff)
			if removed != 7 || err != hostFailure {
				t.Fatalf("RemoveExpired = (%d, %v), want the host's (7, %v)", removed, err, hostFailure)
			}
			if len(host.removals) != 1 || host.removals[0].ctx != ctx || !host.removals[0].cutoff.Equal(cutoff) {
				t.Fatalf("RemoveExpired reached the host as %+v", host.removals)
			}

			if got := logs.warnings(); len(got) != 0 {
				t.Fatalf("warnings = %v, want none", got)
			}
			if wrapper.impl != replay.Registry(host) {
				t.Fatalf("wrapper materialized %T, want the injected registry", wrapper.impl)
			}
		})
	}

	t.Run("provider read once", func(t *testing.T) {
		cfg := replayConfig([]string{"dpop"})
		calls := replayCountingProvider(cfg, &replayRecordingRegistry{})
		cfg.Freeze()

		wrapper := NewlazyReplayRegistry(cfg, nil)
		for i := 0; i < 3; i++ {
			if err := wrapper.Register(context.Background(), replayTestKey, replayTestInstant); err != nil {
				t.Fatalf("Register = %v", err)
			}
		}
		if *calls != 1 {
			t.Fatalf("provider called %d times, want 1", *calls)
		}
	})
}

// While no dependent feature is enabled the seam takes no part in assembly,
// its provider is never called, and using the wrapper is a loud failure.
func TestReplayRegistryNotRequiredWithoutEnabledFeatures(t *testing.T) {
	t.Run("not injected", func(t *testing.T) {
		replayConfig(nil).Freeze()
	})

	t.Run("injected provider is not called by Freeze", func(t *testing.T) {
		cfg := replayConfig(nil)
		calls := replayCountingProvider(cfg, &replayRecordingRegistry{})
		cfg.Freeze()
		if *calls != 0 {
			t.Fatalf("Freeze called the provider %d times, want 0", *calls)
		}
	})

	t.Run("global fallback and nothing injected", func(t *testing.T) {
		cfg := NewServerConfig()
		cfg.AllowInMemoryFallback()
		cfg.Freeze()
	})

	t.Run("using the wrapper panics without reading the seam", func(t *testing.T) {
		cfg := replayConfig(nil)
		calls := replayCountingProvider(cfg, &replayRecordingRegistry{})
		cfg.AllowInMemoryReplayRegistryFallback()
		cfg.Freeze()

		logs := &replayLogCapture{}
		wrapper := NewlazyReplayRegistry(cfg, slog.New(logs))
		first := replayPanicString(t, func() { _ = wrapper.Register(context.Background(), replayTestKey, replayTestInstant) })
		replayRequireContains(t, first, "replay registry", "no feature")

		second := replayPanicString(t, func() { _, _ = wrapper.RemoveExpired(context.Background(), replayTestInstant) })
		if second != first {
			t.Fatalf("second use panicked with %q, want the first value %q", second, first)
		}
		if *calls != 0 {
			t.Fatalf("provider called %d times, want 0", *calls)
		}
		if got := logs.warnings(); len(got) != 0 {
			t.Fatalf("warnings = %v, want none", got)
		}
		if err := wrapper.Close(); err != nil {
			t.Fatalf("Close after the failed use = %v, want nil", err)
		}
	})

	t.Run("closing an unused wrapper reads nothing", func(t *testing.T) {
		cfg := replayConfig(nil)
		calls := replayCountingProvider(cfg, &replayClosingRegistry{})

		logs := &replayLogCapture{}
		wrapper := NewlazyReplayRegistry(cfg, slog.New(logs))
		if err := wrapper.Close(); err != nil {
			t.Fatalf("Close = %v, want nil", err)
		}
		if *calls != 0 {
			t.Fatalf("Close called the provider %d times, want 0", *calls)
		}
		if got := logs.warnings(); len(got) != 0 {
			t.Fatalf("warnings = %v, want none", got)
		}
	})

	t.Run("wrapper without a configuration", func(t *testing.T) {
		wrapper := NewlazyReplayRegistry(nil, nil)
		message := replayPanicString(t, func() { _ = wrapper.Register(context.Background(), replayTestKey, replayTestInstant) })
		replayRequireContains(t, message, "replay registry")
	})
}

// Freeze decides on whether a provider was set; it does not call it, also
// when the seam is required.
func TestReplayRegistryFreezeNeverCallsProvider(t *testing.T) {
	for _, features := range [][]string{{"private_key_jwt"}, {"dpop"}, {"dpop", "private_key_jwt"}} {
		cfg := replayConfig(features)
		calls := replayCountingProvider(cfg, &replayRecordingRegistry{})
		cfg.Freeze()
		if *calls != 0 {
			t.Fatalf("features %v: Freeze called the provider %d times, want 0", features, *calls)
		}
	}
}

// A provider that yields nil satisfies Freeze. What happens at first use then
// depends on the seam's own fallback declaration alone.
func TestReplayRegistryProviderYieldingNil(t *testing.T) {
	ctx := context.Background()

	t.Run("set to nil without fallback declaration", func(t *testing.T) {
		cfg := replayConfig([]string{"private_key_jwt"})
		cfg.SetReplayRegistry(nil)
		cfg.Freeze()

		wrapper := NewlazyReplayRegistry(cfg, nil)
		message := replayPanicString(t, func() { _ = wrapper.Register(ctx, replayTestKey, replayTestInstant) })
		replayRequireContains(t, message, "replay registry", "AllowInMemoryReplayRegistryFallback")
	})

	t.Run("failure repeats with the same value and one provider call", func(t *testing.T) {
		cfg := replayConfig([]string{"dpop"})
		calls := replayCountingProvider(cfg, nil)
		cfg.Freeze()

		logs := &replayLogCapture{}
		wrapper := NewlazyReplayRegistry(cfg, slog.New(logs))
		first := replayPanicString(t, func() { _ = wrapper.Register(ctx, replayTestKey, replayTestInstant) })
		replayRequireContains(t, first, "replay registry", "AllowInMemoryReplayRegistryFallback")

		second := replayPanicString(t, func() { _, _ = wrapper.RemoveExpired(ctx, replayTestInstant) })
		if second != first {
			t.Fatalf("second use panicked with %q, want the first value %q", second, first)
		}
		third := replayPanicString(t, func() { _ = wrapper.Register(ctx, replayTestKey, replayTestInstant) })
		if third != first {
			t.Fatalf("third use panicked with %q, want the first value %q", third, first)
		}
		if *calls != 1 {
			t.Fatalf("provider called %d times, want 1", *calls)
		}
		if got := logs.warnings(); len(got) != 0 {
			t.Fatalf("warnings = %v, want none", got)
		}
		if err := wrapper.Close(); err != nil {
			t.Fatalf("Close after the failed use = %v, want nil", err)
		}
		if *calls != 1 {
			t.Fatalf("Close called the provider; calls = %d, want 1", *calls)
		}
	})

	t.Run("with fallback declaration", func(t *testing.T) {
		cfg := replayConfig([]string{"private_key_jwt"})
		cfg.SetReplayRegistry(nil)
		cfg.AllowInMemoryReplayRegistryFallback()
		cfg.Freeze()

		logs := &replayLogCapture{}
		wrapper := NewlazyReplayRegistry(cfg, slog.New(logs))
		if err := wrapper.Register(ctx, replayTestKey, replayTestInstant); err != nil {
			t.Fatalf("Register = %v, want nil", err)
		}
		warnings := logs.warnings()
		if len(warnings) != 1 {
			t.Fatalf("warnings = %v, want exactly one", warnings)
		}
		replayRequireContains(t, warnings[0], "replay registry", "falling back to in-memory")
		if _, ok := wrapper.impl.(*replay.MemoryRegistry); !ok {
			t.Fatalf("wrapper materialized %T, want *replay.MemoryRegistry", wrapper.impl)
		}
	})

	// The first-use check asks only about this seam: it does not matter
	// whether the configuration was frozen, nor whether the global fallback
	// was declared.
	t.Run("global fallback on an unfrozen configuration does not count", func(t *testing.T) {
		cfg := NewServerConfig()
		cfg.enableReplayDependentFeature("dpop")
		cfg.AllowInMemoryFallback()

		wrapper := NewlazyReplayRegistry(cfg, nil)
		message := replayPanicString(t, func() { _ = wrapper.Register(ctx, replayTestKey, replayTestInstant) })
		replayRequireContains(t, message, "replay registry", "AllowInMemoryReplayRegistryFallback")
	})
}

// The store seams keep their names, their order, their categories and their
// failure text, with or without the replay registry seam in play. The replay
// registry is not one of them.
func TestReplayRegistryLeavesStoreSeamValidationUnchanged(t *testing.T) {
	t.Run("seam list", func(t *testing.T) {
		var names, categories []string
		for _, seam := range NewServerConfig().storeSeams() {
			names = append(names, seam.name)
			categories = append(categories, seam.category.String())
		}
		var want, wantCategories []string
		for _, seam := range replayOtherSeams {
			want = append(want, seam.name)
			wantCategories = append(wantCategories, seam.category.String())
		}
		if len(names) != 12 || !slices.Equal(names, want) {
			t.Fatalf("storeSeams() names = %v, want the 12 names %v", names, want)
		}
		if !slices.Equal(categories, wantCategories) {
			t.Fatalf("storeSeams() categories = %v, want %v", categories, wantCategories)
		}
	})

	missingText := func(name string) string {
		return fmt.Sprintf("store seam %q not injected by host and in-memory fallback not declared", name)
	}

	for _, seam := range replayOtherSeams {
		if seam.category == storeSeamOptional {
			t.Run("missing optional "+seam.name, func(t *testing.T) {
				replayConfig(nil, seam.name).Freeze()
				cfg := replayConfig([]string{"private_key_jwt"}, seam.name)
				cfg.SetReplayRegistry(&replayRecordingRegistry{})
				cfg.Freeze()
			})
			continue
		}
		t.Run("missing "+seam.name, func(t *testing.T) {
			if got := replayPanicString(t, replayConfig(nil, seam.name).Freeze); got != missingText(seam.name) {
				t.Fatalf("Freeze panicked with %q, want %q", got, missingText(seam.name))
			}

			// A required and injected replay registry does not mask it.
			cfg := replayConfig([]string{"private_key_jwt"}, seam.name)
			cfg.SetReplayRegistry(&replayRecordingRegistry{})
			if got := replayPanicString(t, cfg.Freeze); got != missingText(seam.name) {
				t.Fatalf("with the replay registry injected Freeze panicked with %q, want %q", got, missingText(seam.name))
			}

			// Neither does the replay registry's own fallback declaration.
			cfg = replayConfig([]string{"dpop"}, seam.name)
			cfg.AllowInMemoryReplayRegistryFallback()
			if got := replayPanicString(t, cfg.Freeze); got != missingText(seam.name) {
				t.Fatalf("with the replay registry fallback declared Freeze panicked with %q, want %q", got, missingText(seam.name))
			}
		})
	}

	t.Run("mixed injection without declaration", func(t *testing.T) {
		cfg := replayConfig(nil, "device flow store", "session store", "key record store")
		if got := replayPanicString(t, cfg.Freeze); got != missingText("device flow store") {
			t.Fatalf("Freeze panicked with %q, want %q", got, missingText("device flow store"))
		}
	})

	t.Run("nothing injected and nothing declared", func(t *testing.T) {
		first := replayFirstRequiredSeam()
		if got := replayPanicString(t, NewServerConfig().Freeze); got != missingText(first) {
			t.Fatalf("Freeze panicked with %q, want %q", got, missingText(first))
		}
	})

	t.Run("replay registry fallback is not the global fallback", func(t *testing.T) {
		cfg := NewServerConfig()
		cfg.AllowInMemoryReplayRegistryFallback()
		first := replayFirstRequiredSeam()
		if got := replayPanicString(t, cfg.Freeze); got != missingText(first) {
			t.Fatalf("Freeze panicked with %q, want %q", got, missingText(first))
		}
	})
}

func TestServerConfigReplayRegistryTrio(t *testing.T) {
	var absent *ServerConfig
	if got := absent.ReplayRegistry(); got != nil {
		t.Fatalf("ReplayRegistry() on a nil configuration = %v, want nil", got)
	}

	cfg := NewServerConfig()
	if got := cfg.ReplayRegistry(); got != nil {
		t.Fatalf("ReplayRegistry() before any setter = %v, want nil", got)
	}

	direct := &replayRecordingRegistry{}
	cfg.SetReplayRegistry(direct)
	if got := cfg.ReplayRegistry(); got != replay.Registry(direct) {
		t.Fatalf("ReplayRegistry() after SetReplayRegistry = %v, want the registry that was set", got)
	}

	provided := &replayRecordingRegistry{}
	cfg.SetReplayRegistryProvider(func() replay.Registry { return provided })
	if got := cfg.ReplayRegistry(); got != replay.Registry(provided) {
		t.Fatalf("ReplayRegistry() after SetReplayRegistryProvider = %v, want the provider's registry", got)
	}

	cfg.SetReplayRegistry(nil)
	if got := cfg.ReplayRegistry(); got != nil {
		t.Fatalf("ReplayRegistry() after SetReplayRegistry(nil) = %v, want nil", got)
	}

	cfg.SetReplayRegistryProvider(nil)
	if got := cfg.ReplayRegistry(); got != nil {
		t.Fatalf("ReplayRegistry() after SetReplayRegistryProvider(nil) = %v, want nil", got)
	}
}

// Close releases what the wrapper materialized and nothing else.
func TestLazyReplayRegistryClose(t *testing.T) {
	ctx := context.Background()

	t.Run("forwards to a materialized registry that can be closed", func(t *testing.T) {
		closeFailure := errors.New("close failed")
		host := &replayClosingRegistry{closeErr: closeFailure}
		cfg := replayConfig([]string{"private_key_jwt"})
		cfg.SetReplayRegistry(host)

		wrapper := NewlazyReplayRegistry(cfg, nil)
		if err := wrapper.Register(ctx, replayTestKey, replayTestInstant); err != nil {
			t.Fatalf("Register = %v", err)
		}
		if err := wrapper.Close(); err != closeFailure {
			t.Fatalf("Close = %v, want the registry's error %v", err, closeFailure)
		}
		if host.closed != 1 {
			t.Fatalf("registry closed %d times, want 1", host.closed)
		}
	})

	t.Run("materialized registry without Close", func(t *testing.T) {
		cfg := replayConfig([]string{"private_key_jwt"})
		cfg.SetReplayRegistry(&replayRecordingRegistry{})

		wrapper := NewlazyReplayRegistry(cfg, nil)
		if err := wrapper.Register(ctx, replayTestKey, replayTestInstant); err != nil {
			t.Fatalf("Register = %v", err)
		}
		if err := wrapper.Close(); err != nil {
			t.Fatalf("Close = %v, want nil", err)
		}
	})

	t.Run("unused wrapper of a required seam", func(t *testing.T) {
		host := &replayClosingRegistry{}
		cfg := replayConfig([]string{"dpop"})
		calls := replayCountingProvider(cfg, host)

		if err := NewlazyReplayRegistry(cfg, nil).Close(); err != nil {
			t.Fatalf("Close = %v, want nil", err)
		}
		if *calls != 0 || host.closed != 0 {
			t.Fatalf("Close of an unused wrapper read the seam (%d provider calls) or closed the registry (%d times)", *calls, host.closed)
		}
	})
}

// The record of enabled features keeps first-enabled order and holds each
// name once.
func TestReplayDependentFeatureRecord(t *testing.T) {
	cfg := NewServerConfig()
	for _, name := range []string{"private_key_jwt", "dpop"} {
		if cfg.replayDependentFeatureEnabled(name) {
			t.Fatalf("%s reported enabled on a new configuration", name)
		}
	}

	cfg.enableReplayDependentFeature("dpop")
	if !cfg.replayDependentFeatureEnabled("dpop") || cfg.replayDependentFeatureEnabled("private_key_jwt") {
		t.Fatalf("after enabling dpop the record is %v", cfg.replayDependentFeatures)
	}

	cfg.enableReplayDependentFeature("private_key_jwt")
	cfg.enableReplayDependentFeature("dpop")
	cfg.enableReplayDependentFeature("private_key_jwt")
	if want := []string{"dpop", "private_key_jwt"}; !slices.Equal(cfg.replayDependentFeatures, want) {
		t.Fatalf("record = %v, want %v", cfg.replayDependentFeatures, want)
	}

	// The failure text lists the names in that order.
	message := replayPanicString(t, replayConfigFrom(cfg).Freeze)
	if dpop, jwt := strings.Index(message, "dpop"), strings.Index(message, "private_key_jwt"); dpop < 0 || jwt < 0 || dpop > jwt {
		t.Fatalf("failure text %q does not list dpop before private_key_jwt", message)
	}

	var absent *ServerConfig
	if absent.replayDependentFeatureEnabled("dpop") {
		t.Fatal("a nil configuration reports dpop enabled")
	}
}

// replayConfigFrom marks every other seam of cfg injected and returns it.
func replayConfigFrom(cfg *ServerConfig) *ServerConfig {
	for _, seam := range replayOtherSeams {
		seam.inject(cfg)
	}
	return cfg
}
