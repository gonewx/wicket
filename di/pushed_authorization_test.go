// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package di

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket/accessor"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/dp"
	"github.com/gonewx/wicket/infrastructure"
	"github.com/gonewx/wicket/keymgmt"
	models_messages "github.com/gonewx/wicket/models/messages"
	services_impl "github.com/gonewx/wicket/services/impl"
	"github.com/gonewx/wicket/storage"
	storage_memory "github.com/gonewx/wicket/storage/memory"
)

// recordingDataProtectionProvider is a real (non-default) protection
// provider double: it records every purpose it is asked for, and its
// protectors flip every byte.
type recordingDataProtectionProvider struct {
	mu       sync.Mutex
	purposes []string
}

func (p *recordingDataProtectionProvider) Create(purpose string) dp.DataProtector {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.purposes = append(p.purposes, purpose)
	return flippingProtector{}
}

func (p *recordingDataProtectionProvider) created() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.purposes...)
}

type flippingProtector struct{}

func (flippingProtector) Create(string) dp.DataProtector { return flippingProtector{} }

func (flippingProtector) Protect(data []byte) []byte {
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = ^b
	}
	return out
}

func (p flippingProtector) Unprotect(data []byte) ([]byte, error) { return p.Protect(data), nil }

// countingPushedAuthorizationStoreProvider counts how often the store
// provider is called.
type countingPushedAuthorizationStoreProvider struct {
	store storage.PushedAuthorizationRequestStore
	calls atomic.Int64
}

func (p *countingPushedAuthorizationStoreProvider) provide() storage.PushedAuthorizationRequestStore {
	p.calls.Add(1)
	return p.store
}

// pushedAuthorizationConfig returns a configuration with the in-memory
// fallback declared, so only the pushed authorization seams are in play.
func pushedAuthorizationConfig() *ServerConfig {
	cfg := NewServerConfig()
	cfg.AllowInMemoryFallback()
	return cfg
}

func TestPushedAuthorizationDataProtectionSeamRejectsDefaultProvider(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		provider dp.DataProtectionProvider
		enabled  bool
	}{
		"default provider, pushed authorization disabled": {provider: services_impl.NewDataProtectionProvider()},
		"default provider, pushed authorization enabled":  {provider: services_impl.NewDataProtectionProvider(), enabled: true},
		"nil default pointer":                             {provider: (*services_impl.DataProtectionProvider)(nil)},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg := pushedAuthorizationConfig()
			cfg.SetPushedAuthorizationRequestStore(storage_memory.NewMemoryPushedAuthorizationRequestStore())
			cfg.SetPushedAuthorizationDataProtectionProvider(tc.provider)
			if tc.enabled {
				cfg.enablePushedAuthorization()
			}
			text := panicText(t, cfg.Freeze)
			if !strings.Contains(text, `"pushed authorization data protection"`) {
				t.Fatalf("panic %q does not name the pushed authorization data protection seam", text)
			}
		})
	}
}

func TestPushedAuthorizationSeamsRequiredWhenEnabled(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		injectStore    bool
		injectProtect  bool
		storeNil       bool
		wantMissing    string
		globalFallback bool
	}{
		"store missing":                       {injectProtect: true, wantMissing: "pushed authorization request store"},
		"protection missing":                  {injectStore: true, wantMissing: "pushed authorization data protection"},
		"both missing":                        {wantMissing: "pushed authorization request store"},
		"store missing with global fallback":  {injectProtect: true, wantMissing: "pushed authorization request store", globalFallback: true},
		"protection missing, global fallback": {injectStore: true, wantMissing: "pushed authorization data protection", globalFallback: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg := NewServerConfig()
			if tc.globalFallback {
				cfg.AllowInMemoryFallback()
			} else {
				replayConfigFrom(cfg)
			}
			cfg.enablePushedAuthorization()
			if tc.injectStore {
				cfg.SetPushedAuthorizationRequestStore(storage_memory.NewMemoryPushedAuthorizationRequestStore())
			}
			if tc.injectProtect {
				cfg.SetPushedAuthorizationDataProtectionProvider(&recordingDataProtectionProvider{})
			}
			text := panicText(t, cfg.Freeze)
			want := `store seam "` + tc.wantMissing + `" is required by an enabled feature`
			if !strings.Contains(text, want) {
				t.Fatalf("panic %q, want it to contain %q", text, want)
			}
		})
	}
}

func TestPushedAuthorizationSeamsUnusedWhileDisabled(t *testing.T) {
	t.Parallel()

	t.Run("nothing injected", func(t *testing.T) {
		t.Parallel()
		capture := &warnCapture{}
		cfg := pushedAuthorizationConfig()
		cfg.SetLogger(slog.New(capture))
		cfg.Freeze()
		for _, seam := range capture.warned() {
			if strings.Contains(seam, "pushed authorization") {
				t.Fatalf("Freeze warned about %q although pushed authorization is disabled", seam)
			}
		}
		if _, err := cfg.pushedAuthorizationRequestStoreForFeature(); err == nil {
			t.Fatal("store seam usable although pushed authorization is disabled")
		}
		if _, err := cfg.pushedAuthorizationProtectorForFeature(); err == nil {
			t.Fatal("protection seam usable although pushed authorization is disabled")
		}
	})

	t.Run("both injected", func(t *testing.T) {
		t.Parallel()
		cfg := pushedAuthorizationConfig()
		storeProvider := &countingPushedAuthorizationStoreProvider{store: storage_memory.NewMemoryPushedAuthorizationRequestStore()}
		protection := &recordingDataProtectionProvider{}
		cfg.SetPushedAuthorizationRequestStoreProvider(storeProvider.provide)
		cfg.SetPushedAuthorizationDataProtectionProvider(protection)
		cfg.Freeze()
		if store, err := cfg.pushedAuthorizationRequestStoreForFeature(); err == nil || store != nil {
			t.Fatalf("store seam = %v, %v; want an error while pushed authorization is disabled", store, err)
		}
		if protector, err := cfg.pushedAuthorizationProtectorForFeature(); err == nil || protector != nil {
			t.Fatalf("protection seam = %v, %v; want an error while pushed authorization is disabled", protector, err)
		}
		if calls := storeProvider.calls.Load(); calls != 0 {
			t.Fatalf("store provider called %d times while pushed authorization is disabled", calls)
		}
		if created := protection.created(); len(created) != 0 {
			t.Fatalf("protection provider created %v while pushed authorization is disabled", created)
		}
	})

	t.Run("nil configuration", func(t *testing.T) {
		t.Parallel()
		var cfg *ServerConfig
		if cfg.pushedAuthorizationRequired() {
			t.Fatal("a nil configuration reports pushed authorization enabled")
		}
		if _, err := cfg.pushedAuthorizationRequestStoreForFeature(); err == nil {
			t.Fatal("nil configuration returned a store")
		}
		if _, err := cfg.pushedAuthorizationProtectorForFeature(); err == nil {
			t.Fatal("nil configuration returned a protector")
		}
	})
}

func TestPushedAuthorizationSeamsServeEnabledFeature(t *testing.T) {
	t.Parallel()

	cfg := pushedAuthorizationConfig()
	store := storage_memory.NewMemoryPushedAuthorizationRequestStore()
	storeProvider := &countingPushedAuthorizationStoreProvider{store: store}
	protection := &recordingDataProtectionProvider{}
	cfg.SetPushedAuthorizationRequestStoreProvider(storeProvider.provide)
	cfg.SetPushedAuthorizationDataProtectionProvider(protection)
	cfg.enablePushedAuthorization()
	cfg.Freeze()

	if calls := storeProvider.calls.Load(); calls != 0 {
		t.Fatalf("Freeze called the store provider %d times, want 0", calls)
	}
	for i := 0; i < 3; i++ {
		got, err := cfg.pushedAuthorizationRequestStoreForFeature()
		if err != nil {
			t.Fatalf("store seam: %v", err)
		}
		if got != store {
			t.Fatalf("store seam = %v, want the injected store", got)
		}
	}
	if calls := storeProvider.calls.Load(); calls != 1 {
		t.Fatalf("store provider called %d times, want exactly 1", calls)
	}

	protector, err := cfg.pushedAuthorizationProtectorForFeature()
	if err != nil {
		t.Fatalf("protection seam: %v", err)
	}
	if created := protection.created(); !slices.Equal(created, []string{storage.PushedAuthorizationRequestPurpose}) {
		t.Fatalf("protection provider created %v, want only the pushed authorization purpose", created)
	}
	parameters := url.Values{"client_id": {"client-a"}, "scope": {"openid"}}
	payload, err := storage.ProtectPushedAuthorizationParameters(protector, parameters)
	if err != nil {
		t.Fatalf("protect: %v", err)
	}
	if strings.Contains(string(payload), "client-a") {
		t.Fatalf("payload carries plaintext: %s", payload)
	}
	got, err := storage.UnprotectPushedAuthorizationParameters(protector, payload)
	if err != nil || !reflect.DeepEqual(got, parameters) {
		t.Fatalf("round trip = %v, %v; want %v", got, err, parameters)
	}
}

// nilCreatingDataProtectionProvider creates no protector.
type nilCreatingDataProtectionProvider struct{}

func (nilCreatingDataProtectionProvider) Create(string) dp.DataProtector { return nil }

func TestPushedAuthorizationProtectorFailsWhileEnabled(t *testing.T) {
	t.Parallel()

	tests := map[string]dp.DataProtectionProvider{
		"no provider injected":      nil,
		"default provider":          services_impl.NewDataProtectionProvider(),
		"provider creating nothing": nilCreatingDataProtectionProvider{},
	}
	for name, provider := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg := NewServerConfig()
			if provider != nil {
				cfg.SetPushedAuthorizationDataProtectionProvider(provider)
			}
			cfg.enablePushedAuthorization()
			protector, err := cfg.pushedAuthorizationProtectorForFeature()
			if protector != nil || err == nil {
				t.Fatalf("protection seam = %v, %v; want nil and an error", protector, err)
			}
			if !strings.Contains(err.Error(), `"pushed authorization data protection"`) {
				t.Fatalf("error %q does not name the seam", err)
			}
		})
	}
}

func TestPushedAuthorizationStoreSeamRejectsNilProvidedStore(t *testing.T) {
	t.Parallel()

	cfg := pushedAuthorizationConfig()
	storeProvider := &countingPushedAuthorizationStoreProvider{}
	cfg.SetPushedAuthorizationRequestStoreProvider(storeProvider.provide)
	cfg.SetPushedAuthorizationDataProtectionProvider(&recordingDataProtectionProvider{})
	cfg.enablePushedAuthorization()
	cfg.Freeze()
	for i := 0; i < 2; i++ {
		store, err := cfg.pushedAuthorizationRequestStoreForFeature()
		if err == nil || store != nil {
			t.Fatalf("store seam = %v, %v; want an error for a provider returning nil", store, err)
		}
		if !strings.Contains(err.Error(), `"pushed authorization request store"`) {
			t.Fatalf("error %q does not name the seam", err)
		}
	}
	if calls := storeProvider.calls.Load(); calls != 1 {
		t.Fatalf("store provider called %d times, want exactly 1", calls)
	}
}

// pinnedKeyRecord resolves the key manager through the container of root,
// with key management enabled, lets it create a signing key and returns the
// record it wrote to the injected record store.
//
// The container builds its key manager singleton eagerly in NewRoot, while
// key management is still disabled by default. To run the container's own
// factory with key management enabled, the test enables it in the resolved
// options and clears the generated singleton state so the next resolution
// runs the registered factory again.
func pinnedKeyRecord(t *testing.T, root *Root, records *keymgmt.MemoryRecordStore) *keymgmt.Record {
	t.Helper()
	godi.GetRequired[*config_options.WicketOptions](root).KeyManagement.Enabled = true
	root.st_Ptr_Manager = 0
	manager := godi.GetRequired[*keymgmt.Manager](root)
	if !manager.Enabled() {
		t.Fatal("re-resolved key manager is not enabled")
	}
	if _, err := manager.SigningCandidates(context.Background()); err != nil {
		t.Fatalf("key manager signing candidates: %v", err)
	}
	stored, err := records.List(context.Background())
	if err != nil {
		t.Fatalf("list key records: %v", err)
	}
	if len(stored) != 1 {
		t.Fatalf("key records = %d, want 1", len(stored))
	}
	return stored[0]
}

// pinnedMessageCookie writes a consent message through the container's
// message cookie in a request scope of root and returns the cookie value.
func pinnedMessageCookie(t *testing.T, root *Root) string {
	t.Helper()
	scope := root.CreateScope()
	t.Cleanup(func() { _ = scope.Close() })
	contextAccessor := godi.GetRequired[accessor.HttpContextAccessor](scope)
	contextAccessor.SetRequest(httptest.NewRequest("GET", "https://wicket.test/consent", nil))
	recorder := httptest.NewRecorder()
	contextAccessor.(accessor.HttpResponseWriterAccessor).SetResponseWriter(recorder)

	cookie := godi.GetRequired[*infrastructure.MessageCookie[*models_messages.ConsentResponse]](scope)
	message := models_messages.NewMessageWithCreated(&models_messages.ConsentResponse{ScopesValuesConsented: []string{"openid"}}, 42)
	if err := cookie.Write("pinned", message); err != nil {
		t.Fatalf("write message cookie: %v", err)
	}
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("message cookie wrote %d cookies, want 1", len(cookies))
	}
	return cookies[0].Value
}

// TestPushedAuthorizationSeamLeavesContainerDataProtectionUnchanged pins the
// container's dp.DataProtectionProvider binding: with pushed authorization
// enabled and a non-default provider on its seam, key management and message
// cookies still protect with the container's default provider, and the
// pushed authorization provider is only reached through its own seam.
func TestPushedAuthorizationSeamLeavesContainerDataProtectionUnchanged(t *testing.T) {
	t.Parallel()

	assemble := func(t *testing.T, withPushedAuthorization bool) (*Root, *keymgmt.MemoryRecordStore, *recordingDataProtectionProvider) {
		t.Helper()
		root := newClientSeamRoot(t)
		cfg := root.ServerConfig()
		records := keymgmt.NewMemoryRecordStore()
		cfg.SetRecordStore(records)
		cfg.AllowInMemoryFallback()
		protection := &recordingDataProtectionProvider{}
		if withPushedAuthorization {
			cfg.SetPushedAuthorizationRequestStore(storage_memory.NewMemoryPushedAuthorizationRequestStore())
			cfg.SetPushedAuthorizationDataProtectionProvider(protection)
			cfg.enablePushedAuthorization()
		}
		cfg.Freeze()
		return root, records, protection
	}

	defaultProtector := services_impl.NewDataProtectionProvider().Create("pinned")
	recoverKey := func(t *testing.T, record *keymgmt.Record) {
		t.Helper()
		plain, err := defaultProtector.Unprotect(record.ProtectedPrivateMaterial)
		if err != nil {
			t.Fatalf("default provider cannot unprotect the key record: %v", err)
		}
		if _, err := x509.ParsePKCS8PrivateKey(plain); err != nil {
			t.Fatalf("key record unprotected by the default provider is not PKCS#8: %v", err)
		}
	}

	baselineRoot, baselineRecords, _ := assemble(t, false)
	baseline := pinnedKeyRecord(t, baselineRoot, baselineRecords)
	recoverKey(t, baseline)

	root, records, protection := assemble(t, true)
	if provider := godi.GetRequired[dp.DataProtectionProvider](root); reflect.TypeOf(provider) != reflect.TypeFor[*services_impl.DataProtectionProvider]() {
		t.Fatalf("container data protection provider = %T, want *services_impl.DataProtectionProvider", provider)
	}

	record := pinnedKeyRecord(t, root, records)
	recoverKey(t, record)
	if record.Format != baseline.Format {
		t.Fatalf("key record format = %q, want %q as without the pushed authorization seams", record.Format, baseline.Format)
	}

	value := pinnedMessageCookie(t, root)
	plain, err := defaultProtector.Unprotect([]byte(value))
	if err != nil {
		t.Fatalf("default provider cannot unprotect the message cookie: %v", err)
	}
	var message models_messages.Message[*models_messages.ConsentResponse]
	if err := json.Unmarshal(plain, &message); err != nil || message.Created != 42 || message.Data == nil || !slices.Equal(message.Data.ScopesValuesConsented, []string{"openid"}) {
		t.Fatalf("message cookie unprotected by the default provider = %+v, %v; want the written message", message, err)
	}

	if created := protection.created(); len(created) != 0 {
		t.Fatalf("pushed authorization provider created %v outside its seam, want nothing", created)
	}
	if _, err := root.ServerConfig().pushedAuthorizationProtectorForFeature(); err != nil {
		t.Fatalf("pushed authorization protection seam: %v", err)
	}
	if created := protection.created(); !slices.Equal(created, []string{storage.PushedAuthorizationRequestPurpose}) {
		t.Fatalf("pushed authorization provider created %v, want only its purpose once", created)
	}
}
