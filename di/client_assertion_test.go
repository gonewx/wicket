// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package di

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/clientassertion"
	"github.com/gonewx/wicket/handlers"
	"github.com/gonewx/wicket/replay"
	"github.com/gonewx/wicket/storage"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/validators"
)

func newAssertionRoot(t *testing.T) (*Root, *ServerConfig) {
	t.Helper()
	root, err := NewRoot()
	if err != nil {
		t.Fatalf("NewRoot: %v", err)
	}
	t.Cleanup(func() { _ = root.Close() })
	cfg := root.ServerConfig()
	cfg.AllowInMemoryFallback()
	return root, cfg
}

func panicText(t *testing.T, action func()) (text string) {
	t.Helper()
	defer func() {
		recovered := recover()
		if recovered == nil {
			t.Fatalf("no panic")
		}
		text = fmt.Sprint(recovered)
	}()
	action()
	return ""
}

// heldValidatorType names the dynamic type of the validator a handler holds.
func heldValidatorType(handler any, field string) string {
	return reflect.ValueOf(handler).Elem().FieldByName(field).Elem().Type().String()
}

func resolveAuthenticatingHandlers(root *Root) map[string]string {
	return map[string]string{
		"token":         heldValidatorType(godi.GetRequired[*handlers.TokenHandler](root), "clientValidator"),
		"revocation":    heldValidatorType(godi.GetRequired[*handlers.TokenRevocationHandler](root), "clientValidator"),
		"ciba":          heldValidatorType(godi.GetRequired[*handlers.BackchannelAuthenticationHandler](root), "clientValidator"),
		"device":        heldValidatorType(godi.GetRequired[*handlers.DeviceAuthorizationHandler](root), "clientValidator"),
		"introspection": heldValidatorType(godi.GetRequired[*handlers.IntrospectionHandler](root), "apiValidator"),
	}
}

func registeredAssertionClient() *storage_models.Client {
	client := storage_models.NewClient()
	client.ClientId = "assertion-client"
	client.TokenEndpointAuthMethod = "private_key_jwt"
	client.Jwks = `{"keys":[]}`
	return client
}

func TestPrivateKeyJwtNotEnabledLeavesTheAssemblyAsItWas(t *testing.T) {
	root, cfg := newAssertionRoot(t)
	var seamReads atomic.Int64
	cfg.SetReplayRegistryProvider(func() replay.Registry {
		seamReads.Add(1)
		return replay.NewMemoryRegistry()
	})
	cfg.SetClients([]*storage_models.Client{registeredAssertionClient()})
	cfg.Freeze()

	if cfg.PrivateKeyJwtEnabled() {
		t.Fatalf("feature reported enabled")
	}
	if got := cfg.PrivateKeyJwtOptions(); !reflect.DeepEqual(got, clientassertion.Options{}) {
		t.Fatalf("options of a feature that is not enabled: %+v", got)
	}

	methods := godi.GetRequired[validators.SecretsListParser](root).GetAvailableAuthenticationMethods()
	want := []string{wicket.EndpointAuthenticationMethodsBasicAuthentication, wicket.EndpointAuthenticationMethodsPostBody}
	if !slices.Equal(methods, want) {
		t.Fatalf("authentication methods %v, want %v", methods, want)
	}
	if algorithms, ok := clientAssertionSigningAlgorithms(root); ok || algorithms != nil {
		t.Fatalf("signing algorithms without the feature: %v", algorithms)
	}

	for endpoint, held := range resolveAuthenticatingHandlers(root) {
		if strings.Contains(held, "clientassertion") {
			t.Errorf("%s handler holds %s, want the registered validator itself", endpoint, held)
		}
	}
	inner := reflect.TypeOf(godi.GetRequired[validators.ClientSecretValidator](root))
	if got := reflect.TypeOf(clientAuthenticatorFromProvider(root)); got != inner {
		t.Fatalf("client authenticator %s, want %s", got, inner)
	}
	innerApi := reflect.TypeOf(godi.GetRequired[validators.ApiSecretValidator](root))
	if got := reflect.TypeOf(apiAuthenticatorFromProvider(root)); got != innerApi {
		t.Fatalf("api authenticator %s, want %s", got, innerApi)
	}
	_ = godi.GetRequired[*handlers.DiscoveryHandler](root)

	if first, second := godi.GetRequired[*clientassertion.KeySource](root), godi.GetRequired[*clientassertion.KeySource](root); first == nil || first != second {
		t.Fatalf("key source is not a singleton")
	}

	// A client registered for the method does not load while the feature is
	// not enabled.
	client, err := godi.GetRequired[storage.ClientStore](root).FindClientById(context.Background(), "assertion-client")
	if err == nil || client != nil {
		t.Fatalf("client loaded although its authentication method is not enabled: %+v, %v", client, err)
	}

	if got := seamReads.Load(); got != 0 {
		t.Fatalf("replay registry seam read %d times without the feature", got)
	}
}

func TestPrivateKeyJwtEnabledAfterTheRootIsBuilt(t *testing.T) {
	root, cfg := newAssertionRoot(t)
	cfg.SetClients([]*storage_models.Client{registeredAssertionClient()})
	cfg.SetReplayRegistry(replay.NewMemoryRegistry())
	cfg.EnablePrivateKeyJwt(clientassertion.Options{SigningAlgorithms: []string{"PS256", "ES256"}})
	cfg.EnablePrivateKeyJwt(clientassertion.Options{SigningAlgorithms: []string{"ES256", "PS256"}})
	cfg.Freeze()

	if !cfg.PrivateKeyJwtEnabled() || len(cfg.replayDependentFeatures) != 1 {
		t.Fatalf("enablement record: %v", cfg.replayDependentFeatures)
	}
	methods := godi.GetRequired[validators.SecretsListParser](root).GetAvailableAuthenticationMethods()
	if !slices.Contains(methods, "private_key_jwt") {
		t.Fatalf("authentication methods %v miss private_key_jwt", methods)
	}
	algorithms, ok := clientAssertionSigningAlgorithms(root)
	if !ok || !slices.Equal(algorithms, []string{"ES256", "PS256"}) {
		t.Fatalf("signing algorithms %v, %v", algorithms, ok)
	}

	held := resolveAuthenticatingHandlers(root)
	for _, endpoint := range []string{"token", "revocation", "ciba", "device"} {
		if held[endpoint] != "*clientassertion.ClientAuthenticator" {
			t.Errorf("%s handler holds %s", endpoint, held[endpoint])
		}
	}
	if held["introspection"] != "*clientassertion.ApiAuthenticator" {
		t.Errorf("introspection handler holds %s", held["introspection"])
	}
	// The registered validator itself is still what the container resolves.
	if got := reflect.TypeOf(godi.GetRequired[validators.ClientSecretValidator](root)).String(); strings.Contains(got, "clientassertion") {
		t.Fatalf("container resolves %s for the validator interface", got)
	}

	client, err := godi.GetRequired[storage.ClientStore](root).FindClientById(context.Background(), "assertion-client")
	if err != nil || client == nil {
		t.Fatalf("registered client does not load in an enabled assembly: %v", err)
	}
}

func TestPrivateKeyJwtOptionsAreCopies(t *testing.T) {
	cfg := NewServerConfig()
	algorithms := []string{"ES256"}
	cfg.EnablePrivateKeyJwt(clientassertion.Options{SigningAlgorithms: algorithms, ClockSkew: 7 * time.Second})
	algorithms[0] = "none"
	got := cfg.PrivateKeyJwtOptions()
	if !slices.Equal(got.SigningAlgorithms, []string{"ES256"}) || got.ClockSkew != 7*time.Second {
		t.Fatalf("options: %+v", got)
	}
	got.SigningAlgorithms[0] = "none"
	if again := cfg.PrivateKeyJwtOptions(); again.SigningAlgorithms[0] != "ES256" {
		t.Fatalf("stored options changed through a returned copy")
	}
	defaults := clientassertion.DefaultOptions()
	if got.MaxAssertionLifetime != defaults.MaxAssertionLifetime || got.MaxAssertionBytes != defaults.MaxAssertionBytes ||
		got.JwksFetchTimeout != defaults.JwksFetchTimeout || got.MaxJwksResponseBytes != defaults.MaxJwksResponseBytes ||
		got.JwksCacheLifetime != defaults.JwksCacheLifetime || got.JwksMinRefreshInterval != defaults.JwksMinRefreshInterval {
		t.Fatalf("unset fields did not take their defaults: %+v", got)
	}

	var missing *ServerConfig
	if missing.PrivateKeyJwtEnabled() {
		t.Fatalf("nil configuration reports the feature enabled")
	}
}

func TestFreezeRequirementsOfPrivateKeyJwt(t *testing.T) {
	t.Run("registry neither injected nor fallback declared", func(t *testing.T) {
		cfg := NewServerConfig()
		cfg.AllowInMemoryFallback()
		cfg.EnablePrivateKeyJwt(clientassertion.Options{})
		text := panicText(t, cfg.Freeze)
		if !strings.Contains(text, "replay registry") || !strings.Contains(text, "private_key_jwt") {
			t.Fatalf("panic text %q", text)
		}
	})
	t.Run("fallback declared", func(t *testing.T) {
		cfg := NewServerConfig()
		cfg.AllowInMemoryFallback()
		cfg.AllowInMemoryReplayRegistryFallback()
		cfg.EnablePrivateKeyJwt(clientassertion.Options{})
		cfg.Freeze()
	})
	t.Run("invalid options", func(t *testing.T) {
		for name, options := range map[string]clientassertion.Options{
			"symmetric algorithm": {SigningAlgorithms: []string{"HS256"}},
			"none":                {SigningAlgorithms: []string{"none"}},
			"skew":                {ClockSkew: time.Hour},
			"negative":            {MaxAssertionBytes: -1},
		} {
			cfg := NewServerConfig()
			cfg.AllowInMemoryFallback()
			cfg.SetReplayRegistry(replay.NewMemoryRegistry())
			cfg.EnablePrivateKeyJwt(options)
			if text := panicText(t, cfg.Freeze); !strings.HasPrefix(text, "private_key_jwt options invalid: ") {
				t.Fatalf("%s: panic text %q", name, text)
			}
		}
	})
	t.Run("enabling after Freeze", func(t *testing.T) {
		cfg := NewServerConfig()
		cfg.AllowInMemoryFallback()
		cfg.Freeze()
		text := panicText(t, func() { cfg.EnablePrivateKeyJwt(clientassertion.Options{}) })
		if !strings.Contains(text, "EnablePrivateKeyJwt") || !strings.Contains(text, "after Freeze") {
			t.Fatalf("panic text %q", text)
		}
		if cfg.PrivateKeyJwtEnabled() {
			t.Fatalf("feature enabled by a rejected call")
		}
	})
}

// signedAssertion renders an ES256 assertion and the JWK Set of its key.
func signedAssertion(t *testing.T, claims map[string]any) (assertion string, keySet string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	point, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	encode := base64.RawURLEncoding.EncodeToString
	keySet = fmt.Sprintf(`{"keys":[{"kty":"EC","crv":"P-256","x":%q,"y":%q}]}`, encode(point[1:33]), encode(point[33:]))
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	input := encode([]byte(`{"alg":"ES256"}`)) + "." + encode(payload)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return input + "." + encode(signature), keySet
}

func TestPrivateKeyJwtOptionsDeclaredAfterTheRootReachTheVerifier(t *testing.T) {
	const audience = "https://server.example"
	verifyWithExpiry := func(t *testing.T, root *Root, offset time.Duration) error {
		assertion, keySet := signedAssertion(t, map[string]any{
			"iss": "client", "sub": "client", "aud": audience,
			"exp": time.Now().Add(offset).Unix(), "jti": fmt.Sprintf("jti-%d", time.Now().UnixNano()),
		})
		verifier := godi.GetRequired[*clientassertion.Verifier](root)
		return verifier.Verify(context.Background(), clientassertion.Principal{ID: "client", Jwks: keySet}, audience, assertion)
	}

	// An assertion that expired 30 seconds ago is inside the default skew of
	// 60 seconds and outside a declared skew of 7 seconds.
	root, cfg := newAssertionRoot(t)
	cfg.SetReplayRegistry(replay.NewMemoryRegistry())
	cfg.EnablePrivateKeyJwt(clientassertion.Options{ClockSkew: 7 * time.Second})
	cfg.Freeze()
	if err := verifyWithExpiry(t, root, time.Minute); err != nil {
		t.Fatalf("valid assertion: %v", err)
	}
	if err := verifyWithExpiry(t, root, -30*time.Second); err == nil {
		t.Fatalf("assertion accepted with the default skew although 7s was declared")
	}

	defaults, defaultsCfg := newAssertionRoot(t)
	defaultsCfg.SetReplayRegistry(replay.NewMemoryRegistry())
	defaultsCfg.EnablePrivateKeyJwt(clientassertion.Options{})
	defaultsCfg.Freeze()
	if err := verifyWithExpiry(t, defaults, -30*time.Second); err != nil {
		t.Fatalf("assertion inside the default skew: %v", err)
	}
}

// closingRegistry is a registry adapter double that counts Close calls.
type closingRegistry struct {
	replay.Registry
	closes atomic.Int64
}

func (r *closingRegistry) Close() error {
	r.closes.Add(1)
	return nil
}

func TestReplayRegistryWrapperIsResolvableAndClosedWithTheRoot(t *testing.T) {
	root, err := NewRoot()
	if err != nil {
		t.Fatalf("NewRoot: %v", err)
	}
	cfg := root.ServerConfig()
	cfg.AllowInMemoryFallback()
	adapter := &closingRegistry{Registry: replay.NewMemoryRegistry()}
	cfg.SetReplayRegistry(adapter)
	cfg.EnablePrivateKeyJwt(clientassertion.Options{})
	cfg.Freeze()

	registry := godi.GetRequired[replay.Registry](root)
	if _, wrapped := registry.(*lazyReplayRegistry); !wrapped {
		t.Fatalf("container resolves %T, want the lazy wrapper", registry)
	}
	key, err := replay.Key(replay.PurposeClientAssertion(), "client", "jti")
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Register(context.Background(), key, time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := registry.Register(context.Background(), key, time.Now().Add(time.Minute)); !errors.Is(err, replay.ErrDuplicateHandle) {
		t.Fatalf("second Register: %v", err)
	}
	if err := root.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := adapter.closes.Load(); got != 1 {
		t.Fatalf("adapter closed %d times, want 1", got)
	}
	_ = root.Close()
	if got := adapter.closes.Load(); got != 1 {
		t.Fatalf("adapter closed %d times after a second Close, want 1", got)
	}
}

func TestReplayRegistryFallbackIsReachableForRemoveExpired(t *testing.T) {
	root, cfg := newAssertionRoot(t)
	cfg.AllowInMemoryReplayRegistryFallback()
	cfg.EnablePrivateKeyJwt(clientassertion.Options{})
	cfg.Freeze()

	registry := godi.GetRequired[replay.Registry](root)
	key, err := replay.Key(replay.PurposeClientAssertion(), "client", "jti")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := registry.Register(context.Background(), key, now.Add(-time.Minute)); err != nil {
		t.Fatalf("Register: %v", err)
	}
	removed, err := godi.GetRequired[replay.Registry](root).RemoveExpired(context.Background(), now)
	if err != nil || removed != 1 {
		t.Fatalf("RemoveExpired = %d, %v; want 1, nil", removed, err)
	}
}

func TestReplayRegistryWrapperMaterializesOnceUnderConcurrentFirstUse(t *testing.T) {
	root, cfg := newAssertionRoot(t)
	var seamReads atomic.Int64
	shared := replay.NewMemoryRegistry()
	cfg.SetReplayRegistryProvider(func() replay.Registry {
		seamReads.Add(1)
		return shared
	})
	cfg.EnablePrivateKeyJwt(clientassertion.Options{})
	cfg.Freeze()
	registry := godi.GetRequired[replay.Registry](root)

	const callers = 64
	errs := make([]error, callers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key, err := replay.Key(replay.PurposeClientAssertion(), "client", fmt.Sprintf("jti-%d", i))
			if err != nil {
				errs[i] = err
				return
			}
			<-start
			errs[i] = registry.Register(context.Background(), key, time.Now().Add(time.Minute))
		}(i)
	}
	close(start)
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("caller %d: %v", i, err)
		}
	}
	if got := seamReads.Load(); got != 1 {
		t.Fatalf("replay registry seam read %d times, want 1", got)
	}
}
