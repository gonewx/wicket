// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package di

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket/dpop"
	"github.com/gonewx/wicket/handlers"
	"github.com/gonewx/wicket/replay"
)

// spyNonceKeys counts its reads and answers with keys and err.
type spyNonceKeys struct {
	reads   atomic.Int64
	current dpop.NonceKey
	err     error
}

func (s *spyNonceKeys) NonceKeys() (dpop.NonceKey, []dpop.NonceKey, error) {
	s.reads.Add(1)
	return s.current, nil, s.err
}

func validNonceKey() dpop.NonceKey {
	return dpop.NonceKey{Id: "k1", Secret: bytes.Repeat([]byte{7}, 32)}
}

// nonceConfig is a config with in-memory fallbacks and a replay registry,
// DPoP enabled with options.
func nonceConfig(options dpop.Options) *ServerConfig {
	cfg := NewServerConfig()
	cfg.AllowInMemoryFallback()
	cfg.SetReplayRegistry(replay.NewMemoryRegistry())
	cfg.EnableDPoP(options)
	return cfg
}

// heldNonces reports whether the token handler of root serves server
// nonces.
func heldNonces(root *Root) bool {
	handler := godi.GetRequired[*handlers.TokenHandler](root)
	held := reflect.ValueOf(handler).Elem().FieldByName("dpop")
	if held.IsNil() {
		return false
	}
	return !held.Elem().FieldByName("nonces").IsNil()
}

func TestFreezeRequirementsOfDPoPNonceKeys(t *testing.T) {
	t.Run("seam missing", func(t *testing.T) {
		text := panicText(t, nonceConfig(dpop.Options{RequireNonce: true}).Freeze)
		if !strings.Contains(text, "dpop nonce key") || !strings.Contains(text, "required by an enabled feature") {
			t.Fatalf("panic text %q", text)
		}
	})
	t.Run("in-memory fallback does not exempt the seam", func(t *testing.T) {
		cfg := nonceConfig(dpop.Options{RequireNonce: true})
		cfg.AllowInMemoryFallback()
		cfg.AllowInMemoryReplayRegistryFallback()
		if text := panicText(t, cfg.Freeze); !strings.Contains(text, "dpop nonce key") {
			t.Fatalf("panic text %q", text)
		}
	})
	t.Run("nil source stands for none", func(t *testing.T) {
		cfg := nonceConfig(dpop.Options{RequireNonce: true})
		cfg.SetDPoPNonceKeys(&spyNonceKeys{current: validNonceKey()})
		cfg.SetDPoPNonceKeys(nil)
		if text := panicText(t, cfg.Freeze); !strings.Contains(text, "dpop nonce key") {
			t.Fatalf("panic text %q", text)
		}
	})
	t.Run("invalid keys", func(t *testing.T) {
		for name, key := range map[string]dpop.NonceKey{
			"short secret": {Id: "k1", Secret: make([]byte, 31)},
			"empty id":     {Secret: make([]byte, 32)},
			"long id":      {Id: strings.Repeat("k", 33), Secret: make([]byte, 32)},
			"bad id":       {Id: "k 1", Secret: make([]byte, 32)},
		} {
			cfg := nonceConfig(dpop.Options{RequireNonce: true})
			cfg.SetDPoPNonceKeys(&spyNonceKeys{current: key})
			if text := panicText(t, cfg.Freeze); !strings.Contains(text, "dpop nonce key") {
				t.Fatalf("%s: panic text %q", name, text)
			}
		}
	})
	t.Run("source fails", func(t *testing.T) {
		cfg := nonceConfig(dpop.Options{RequireNonce: true})
		cfg.SetDPoPNonceKeys(&spyNonceKeys{err: errors.New("down")})
		if text := panicText(t, cfg.Freeze); !strings.Contains(text, "dpop nonce key") {
			t.Fatalf("panic text %q", text)
		}
	})
	t.Run("valid keys", func(t *testing.T) {
		cfg := nonceConfig(dpop.Options{RequireNonce: true})
		source, err := dpop.NewStaticNonceKeys(validNonceKey())
		if err != nil {
			t.Fatal(err)
		}
		cfg.SetDPoPNonceKeys(source)
		cfg.Freeze()
	})
	t.Run("invalid nonce lifetime", func(t *testing.T) {
		for name, lifetime := range map[string]time.Duration{"negative": -time.Second, "too long": time.Hour} {
			cfg := nonceConfig(dpop.Options{RequireNonce: true, NonceLifetime: lifetime})
			cfg.SetDPoPNonceKeys(&spyNonceKeys{current: validNonceKey()})
			if text := panicText(t, cfg.Freeze); !strings.HasPrefix(text, "dpop options invalid: ") {
				t.Fatalf("%s: panic text %q", name, text)
			}
		}
	})
	t.Run("setting the seam after Freeze", func(t *testing.T) {
		cfg := NewServerConfig()
		cfg.AllowInMemoryFallback()
		cfg.Freeze()
		text := panicText(t, func() { cfg.SetDPoPNonceKeys(&spyNonceKeys{}) })
		if !strings.Contains(text, "SetDPoPNonceKeys") || !strings.Contains(text, "after Freeze") {
			t.Fatalf("panic text %q", text)
		}
	})
}

func TestDPoPNonceKeysNotReadWhileNotRequired(t *testing.T) {
	for name, enable := range map[string]bool{"DPoP not enabled": false, "DPoP enabled without nonces": true} {
		t.Run(name, func(t *testing.T) {
			root, cfg := newAssertionRoot(t)
			cfg.SetReplayRegistry(replay.NewMemoryRegistry())
			spy := &spyNonceKeys{current: validNonceKey()}
			cfg.SetDPoPNonceKeys(spy)
			if enable {
				cfg.EnableDPoP(dpop.Options{})
			}
			cfg.Freeze()

			if heldNonces(root) {
				t.Fatal("token handler serves nonces although they are not required")
			}
			if _, err := cfg.dpopNonceKeysForFeature(); err == nil {
				t.Fatal("seam handed out although nonces are not required")
			}
			if got := spy.reads.Load(); got != 0 {
				t.Fatalf("nonce key source read %d times", got)
			}
		})
	}
}

func TestDPoPNonceKeysServeTheTokenHandler(t *testing.T) {
	root, cfg := newAssertionRoot(t)
	cfg.SetReplayRegistry(replay.NewMemoryRegistry())
	spy := &spyNonceKeys{current: validNonceKey()}
	cfg.SetDPoPNonceKeys(spy)
	cfg.EnableDPoP(dpop.Options{RequireNonce: true})
	cfg.Freeze()

	if got := cfg.DPoPOptions(); !got.RequireNonce || got.NonceLifetime != 5*time.Minute {
		t.Fatalf("options %+v", got)
	}
	if !heldNonces(root) {
		t.Fatal("token handler serves no nonces although they are required")
	}
	source, err := cfg.dpopNonceKeysForFeature()
	if err != nil || source != spy {
		t.Fatalf("seam %v, %v", source, err)
	}
}
