// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package pushedauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/dp"
	"github.com/gonewx/wicket/storage"
	storage_memory "github.com/gonewx/wicket/storage/memory"
	storage_models "github.com/gonewx/wicket/storage/models"
)

// sealingProtector authenticates what it protects with an HMAC tag, so any
// change to a protected value makes Unprotect fail.
type sealingProtector struct{ key []byte }

func (p sealingProtector) Create(string) dp.DataProtector { return p }

func (p sealingProtector) Protect(data []byte) []byte {
	mac := hmac.New(sha256.New, p.key)
	mac.Write(data)
	return append(mac.Sum(nil), data...)
}

func (p sealingProtector) Unprotect(data []byte) ([]byte, error) {
	if len(data) < sha256.Size {
		return nil, errors.New("short")
	}
	mac := hmac.New(sha256.New, p.key)
	mac.Write(data[sha256.Size:])
	if !hmac.Equal(mac.Sum(nil), data[:sha256.Size]) {
		return nil, errors.New("tampered")
	}
	return append([]byte(nil), data[sha256.Size:]...), nil
}

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// failingStore fails every operation with err.
type failingStore struct{ err error }

func (s failingStore) StorePushedAuthorizationRequest(context.Context, string, *storage_models.PushedAuthorizationRequest) error {
	return s.err
}
func (s failingStore) GetPushedAuthorizationRequest(context.Context, string) (*storage_models.PushedAuthorizationRequest, error) {
	return nil, s.err
}
func (s failingStore) TakePushedAuthorizationRequest(context.Context, string) (*storage_models.PushedAuthorizationRequest, error) {
	return nil, s.err
}
func (s failingStore) RemoveExpired(context.Context, time.Time) (int, error) { return 0, s.err }

// failingClientStore fails every lookup with err.
type failingClientStore struct{ err error }

func (s failingClientStore) FindClientById(context.Context, string) (*storage_models.Client, error) {
	return nil, s.err
}

type fixture struct {
	service   *Service
	store     storage.PushedAuthorizationRequestStore
	clock     *testClock
	protector sealingProtector
	clientA   *storage_models.Client
	clientB   *storage_models.Client
}

func newFixture(t *testing.T, options Options) *fixture {
	t.Helper()
	clientA := storage_models.NewClient()
	clientA.ClientId = "client_a"
	clientB := storage_models.NewClient()
	clientB.ClientId = "client_b"
	clients, err := storage_memory.NewMemoryClientStore([]*storage_models.Client{clientA, clientB})
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{
		store:     storage_memory.NewMemoryPushedAuthorizationRequestStore(),
		clock:     &testClock{now: time.Date(2026, 11, 14, 9, 0, 0, 0, time.UTC)},
		protector: sealingProtector{key: []byte("pushed authorization test key")},
		clientA:   clientA,
		clientB:   clientB,
	}
	options.Clock = f.clock
	f.service, err = NewService(f.store, f.protector, clients, options)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) push(t *testing.T, client *storage_models.Client) (string, int) {
	t.Helper()
	uri, expiresIn, err := f.service.Push(context.Background(), client, url.Values{
		wicket.AuthorizeRequestClientId: {client.ClientId},
		wicket.AuthorizeRequestScope:    {"openid"},
	})
	if err != nil {
		t.Fatalf("Push: %v", err)
	}
	return uri, expiresIn
}

func (f *fixture) record(t *testing.T, uri string) *storage_models.PushedAuthorizationRequest {
	t.Helper()
	key, err := storage.PushedAuthorizationRequestKey(uri)
	if err != nil {
		t.Fatal(err)
	}
	record, err := f.store.GetPushedAuthorizationRequest(context.Background(), key)
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	return record
}

func TestNewServiceRejectsInvalidOptions(t *testing.T) {
	t.Parallel()
	clients, _ := storage_memory.NewMemoryClientStore(nil)
	store := storage_memory.NewMemoryPushedAuthorizationRequestStore()
	protector := sealingProtector{key: []byte("k")}
	clock := &testClock{}
	for name, options := range map[string]Options{
		"negative lifetime": {RequestUriLifetime: -time.Second, Clock: clock},
		"negative grace":    {InteractionGracePeriod: -time.Second, Clock: clock},
		"no clock":          {},
	} {
		if _, err := NewService(store, protector, clients, options); err == nil {
			t.Errorf("%s: NewService succeeded", name)
		}
	}
}

func TestPushLifetimes(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		options        Options
		clientLifetime int
		wantExpiresIn  int
		wantEntry      time.Duration
		wantRetention  time.Duration
	}{
		"defaults":        {wantExpiresIn: 60, wantEntry: 60 * time.Second, wantRetention: 60*time.Second + 10*time.Minute},
		"global lifetime": {options: Options{RequestUriLifetime: 90 * time.Second, InteractionGracePeriod: time.Minute}, wantExpiresIn: 90, wantEntry: 90 * time.Second, wantRetention: 150 * time.Second},
		"client lifetime": {clientLifetime: 30, wantExpiresIn: 30, wantEntry: 30 * time.Second, wantRetention: 30*time.Second + 10*time.Minute},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t, tc.options)
			f.clientA.RequestUriLifetime = tc.clientLifetime
			start := f.clock.Now()
			uri, expiresIn := f.push(t, f.clientA)
			if expiresIn != tc.wantExpiresIn {
				t.Errorf("expires_in = %d, want %d", expiresIn, tc.wantExpiresIn)
			}
			if len(uri) <= len(storage.PushedAuthorizationRequestURIPrefix) || uri[:len(storage.PushedAuthorizationRequestURIPrefix)] != storage.PushedAuthorizationRequestURIPrefix {
				t.Errorf("request_uri %q lacks the prefix", uri)
			}
			record := f.record(t, uri)
			if record.ClientId != f.clientA.ClientId {
				t.Errorf("ClientId = %q", record.ClientId)
			}
			if !record.EntryExpiration.Equal(start.Add(tc.wantEntry)) {
				t.Errorf("EntryExpiration = %v, want %v", record.EntryExpiration, start.Add(tc.wantEntry))
			}
			if !record.RetentionExpiration.Equal(start.Add(tc.wantRetention)) {
				t.Errorf("RetentionExpiration = %v, want %v", record.RetentionExpiration, start.Add(tc.wantRetention))
			}
		})
	}
}

func TestPushStoreFailureIsWrapped(t *testing.T) {
	t.Parallel()
	boom := errors.New("boom")
	clients, _ := storage_memory.NewMemoryClientStore(nil)
	service, err := NewService(failingStore{err: boom}, sealingProtector{key: []byte("k")}, clients, Options{Clock: &testClock{}})
	if err != nil {
		t.Fatal(err)
	}
	client := storage_models.NewClient()
	client.ClientId = "c"
	if _, _, err := service.Push(context.Background(), client, url.Values{"client_id": {"c"}}); !errors.Is(err, boom) {
		t.Fatalf("Push error = %v, want wrapping %v", err, boom)
	}
}

func TestResolveEntryAndRoundTrip(t *testing.T) {
	t.Parallel()
	f := newFixture(t, Options{})
	uri, _ := f.push(t, f.clientA)
	ctx := context.Background()

	parameters, receipt, err := f.service.Resolve(ctx, uri, f.clientA.ClientId, "", false)
	if err != nil {
		t.Fatalf("entry Resolve: %v", err)
	}
	if parameters.Get(wicket.AuthorizeRequestScope) != "openid" || receipt == "" {
		t.Fatalf("entry Resolve = %v, %q", parameters, receipt)
	}

	// The entry lifetime passes while the user logs in.
	f.clock.advance(5 * time.Minute)
	if _, _, err := f.service.Resolve(ctx, uri, f.clientA.ClientId, "", true); !errors.Is(err, ErrRequestUriInvalid) {
		t.Fatalf("round trip without receipt = %v, want ErrRequestUriInvalid", err)
	}
	if _, _, err := f.service.Resolve(ctx, uri, f.clientA.ClientId, receipt, false); !errors.Is(err, ErrRequestUriInvalid) {
		t.Fatalf("entry with receipt after expiry = %v, want ErrRequestUriInvalid", err)
	}
	_, kept, err := f.service.Resolve(ctx, uri, f.clientA.ClientId, receipt, true)
	if err != nil {
		t.Fatalf("round trip with receipt: %v", err)
	}
	if kept != receipt {
		t.Fatal("round trip did not keep the receipt")
	}

	// Past the retention, even the round trip fails.
	f.clock.advance(10 * time.Minute)
	if _, _, err := f.service.Resolve(ctx, uri, f.clientA.ClientId, receipt, true); !errors.Is(err, ErrRequestUriInvalid) {
		t.Fatalf("round trip after retention = %v, want ErrRequestUriInvalid", err)
	}
	// Nothing was consumed.
	f.record(t, uri)
}

func TestResolveRejects(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tests := map[string]func(t *testing.T, f *fixture, uri string) (string, string){
		"unknown request_uri": func(t *testing.T, f *fixture, uri string) (string, string) {
			return storage.PushedAuthorizationRequestURIPrefix + "unknown", f.clientA.ClientId
		},
		"no prefix": func(t *testing.T, f *fixture, uri string) (string, string) {
			return "https://rp.example/request", f.clientA.ClientId
		},
		"other client": func(t *testing.T, f *fixture, uri string) (string, string) {
			return uri, f.clientB.ClientId
		},
		"entry expired": func(t *testing.T, f *fixture, uri string) (string, string) {
			f.clock.advance(60 * time.Second)
			return uri, f.clientA.ClientId
		},
		"tampered payload": func(t *testing.T, f *fixture, uri string) (string, string) {
			f.rewrite(t, uri, func(r *storage_models.PushedAuthorizationRequest) { r.Payload = []byte("{}") })
			return uri, f.clientA.ClientId
		},
		"payload of another client": func(t *testing.T, f *fixture, uri string) (string, string) {
			payload, err := storage.ProtectPushedAuthorizationParameters(f.protector, url.Values{wicket.AuthorizeRequestClientId: {f.clientB.ClientId}})
			if err != nil {
				t.Fatal(err)
			}
			f.rewrite(t, uri, func(r *storage_models.PushedAuthorizationRequest) { r.Payload = payload })
			return uri, f.clientA.ClientId
		},
	}
	for name, arrange := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t, Options{})
			uri, _ := f.push(t, f.clientA)
			presented, clientId := arrange(t, f, uri)
			if _, _, err := f.service.Resolve(ctx, presented, clientId, "", false); !errors.Is(err, ErrRequestUriInvalid) {
				t.Fatalf("Resolve = %v, want ErrRequestUriInvalid", err)
			}
		})
	}
}

// rewrite replaces the record stored for uri with a modified copy.
func (f *fixture) rewrite(t *testing.T, uri string, change func(*storage_models.PushedAuthorizationRequest)) {
	t.Helper()
	key, _ := storage.PushedAuthorizationRequestKey(uri)
	record, err := f.store.TakePushedAuthorizationRequest(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	change(record)
	if err := f.store.StorePushedAuthorizationRequest(context.Background(), key, record); err != nil {
		t.Fatal(err)
	}
}

func TestResolveStoreFailureIsNotInvalid(t *testing.T) {
	t.Parallel()
	boom := errors.New("boom")
	clients, _ := storage_memory.NewMemoryClientStore(nil)
	service, _ := NewService(failingStore{err: boom}, sealingProtector{key: []byte("k")}, clients, Options{Clock: &testClock{}})
	_, _, err := service.Resolve(context.Background(), storage.PushedAuthorizationRequestURIPrefix+"x", "c", "", false)
	if !errors.Is(err, boom) || errors.Is(err, ErrRequestUriInvalid) {
		t.Fatalf("Resolve = %v, want the store failure", err)
	}
}

func TestEntryReceiptMustMatch(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tests := map[string]func(t *testing.T, f *fixture, uri string, receipt string) string{
		"forged": func(t *testing.T, f *fixture, uri string, receipt string) string {
			key, _ := storage.PushedAuthorizationRequestKey(uri)
			plain, _ := json.Marshal(entryReceipt{Kind: entryReceiptKind, Key: key, EnteredAt: f.clock.Now().UnixNano()})
			forger := sealingProtector{key: []byte("another key")}
			return base64.RawURLEncoding.EncodeToString(forger.Protect(plain))
		},
		"tampered": func(t *testing.T, f *fixture, uri string, receipt string) string {
			raw, _ := base64.RawURLEncoding.DecodeString(receipt)
			raw[len(raw)-2] ^= 0x01
			return base64.RawURLEncoding.EncodeToString(raw)
		},
		"not base64url": func(t *testing.T, f *fixture, uri string, receipt string) string {
			return "!!" + receipt
		},
		"another request_uri": func(t *testing.T, f *fixture, uri string, receipt string) string {
			other, _ := f.push(t, f.clientA)
			_, otherReceipt, err := f.service.Resolve(ctx, other, f.clientA.ClientId, "", false)
			if err != nil {
				t.Fatal(err)
			}
			return otherReceipt
		},
		"wrong kind": func(t *testing.T, f *fixture, uri string, receipt string) string {
			key, _ := storage.PushedAuthorizationRequestKey(uri)
			plain, _ := json.Marshal(entryReceipt{Kind: "other", Key: key, EnteredAt: f.clock.Now().UnixNano()})
			return base64.RawURLEncoding.EncodeToString(f.protector.Protect(plain))
		},
		"entered in the future": func(t *testing.T, f *fixture, uri string, receipt string) string {
			key, _ := storage.PushedAuthorizationRequestKey(uri)
			plain, _ := json.Marshal(entryReceipt{Kind: entryReceiptKind, Key: key, EnteredAt: f.clock.Now().Add(time.Hour).UnixNano()})
			return base64.RawURLEncoding.EncodeToString(f.protector.Protect(plain))
		},
		"entered after entry expiration": func(t *testing.T, f *fixture, uri string, receipt string) string {
			key, _ := storage.PushedAuthorizationRequestKey(uri)
			plain, _ := json.Marshal(entryReceipt{Kind: entryReceiptKind, Key: key, EnteredAt: f.record(t, uri).EntryExpiration.UnixNano()})
			return base64.RawURLEncoding.EncodeToString(f.protector.Protect(plain))
		},
	}
	for name, forge := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t, Options{})
			uri, _ := f.push(t, f.clientA)
			_, receipt, err := f.service.Resolve(ctx, uri, f.clientA.ClientId, "", false)
			if err != nil {
				t.Fatal(err)
			}
			presented := forge(t, f, uri, receipt)
			// Past the entry lifetime, within the retention.
			f.clock.advance(2 * time.Minute)
			if _, _, err := f.service.Resolve(ctx, uri, f.clientA.ClientId, presented, true); !errors.Is(err, ErrRequestUriInvalid) {
				t.Fatalf("round trip with %s receipt = %v, want ErrRequestUriInvalid", name, err)
			}
		})
	}
}

func TestConsume(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("takes once", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, Options{})
		uri, _ := f.push(t, f.clientA)
		if err := f.service.Consume(ctx, uri, f.clientA.ClientId); err != nil {
			t.Fatalf("Consume: %v", err)
		}
		if err := f.service.Consume(ctx, uri, f.clientA.ClientId); !errors.Is(err, ErrRequestUriConsumed) {
			t.Fatalf("second Consume = %v, want ErrRequestUriConsumed", err)
		}
	})
	t.Run("concurrent takes succeed once", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, Options{})
		uri, _ := f.push(t, f.clientA)
		const n = 16
		errs := make(chan error, n)
		var wg sync.WaitGroup
		for range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs <- f.service.Consume(ctx, uri, f.clientA.ClientId)
			}()
		}
		wg.Wait()
		close(errs)
		won := 0
		for err := range errs {
			switch {
			case err == nil:
				won++
			case !errors.Is(err, ErrRequestUriConsumed):
				t.Errorf("unexpected error %v", err)
			}
		}
		if won != 1 {
			t.Fatalf("%d consumers won, want 1", won)
		}
	})
	t.Run("rejected client keeps the request", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, Options{})
		uri, _ := f.push(t, f.clientA)
		f.clientA.Enabled = false
		if err := f.service.Consume(ctx, uri, f.clientA.ClientId); !errors.Is(err, ErrClientRejected) {
			t.Fatalf("Consume = %v, want ErrClientRejected", err)
		}
		f.record(t, uri)
	})
	t.Run("client store failure", func(t *testing.T) {
		t.Parallel()
		boom := errors.New("boom")
		service, _ := NewService(storage_memory.NewMemoryPushedAuthorizationRequestStore(), sealingProtector{key: []byte("k")}, failingClientStore{err: boom}, Options{Clock: &testClock{}})
		err := service.Consume(ctx, storage.PushedAuthorizationRequestURIPrefix+"x", "c")
		if !errors.Is(err, boom) || errors.Is(err, ErrClientRejected) || errors.Is(err, ErrRequestUriConsumed) {
			t.Fatalf("Consume = %v, want the client store failure", err)
		}
	})
	t.Run("store failure", func(t *testing.T) {
		t.Parallel()
		boom := errors.New("boom")
		client := storage_models.NewClient()
		client.ClientId = "c"
		clients, _ := storage_memory.NewMemoryClientStore([]*storage_models.Client{client})
		service, _ := NewService(failingStore{err: boom}, sealingProtector{key: []byte("k")}, clients, Options{Clock: &testClock{}})
		err := service.Consume(ctx, storage.PushedAuthorizationRequestURIPrefix+"x", "c")
		if !errors.Is(err, boom) || errors.Is(err, ErrRequestUriConsumed) {
			t.Fatalf("Consume = %v, want the store failure", err)
		}
	})
}

func TestRequired(t *testing.T) {
	t.Parallel()
	f := newFixture(t, Options{})
	if f.service.Required(f.clientA) {
		t.Fatal("Required without any requirement")
	}
	f.clientA.RequirePushedAuthorizationRequests = true
	if !f.service.Required(f.clientA) {
		t.Fatal("client requirement ignored")
	}
	g := newFixture(t, Options{RequireForAllClients: true})
	if !g.service.Required(g.clientB) {
		t.Fatal("global requirement ignored")
	}
}
