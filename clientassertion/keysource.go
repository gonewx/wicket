// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package clientassertion

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gonewx/wicket/services"
)

// Principal is the party an assertion has to come from: a client, or an API
// resource, together with where its public keys are registered.
type Principal struct {
	// ID is the client_id or the API resource name.
	ID string
	// Jwks is the registered inline JWK Set document.
	Jwks string
	// JwksUri is the registered JWK Set address.
	JwksUri string
}

// Failure categories. They are written to the log only.
const (
	reasonStructure       = "structure"
	reasonAlgorithm       = "algorithm"
	reasonKeyRegistration = "key_registration"
	reasonKeyUnavailable  = "key_unavailable"
	reasonKeyNotFound     = "key_not_found"
	reasonKeyAmbiguous    = "key_ambiguous"
	reasonSignature       = "signature"
	reasonIssuer          = "issuer"
	reasonSubject         = "subject"
	reasonAudience        = "audience"
	reasonExpired         = "expired"
	reasonLifetime        = "lifetime"
	reasonNotBefore       = "not_before"
	reasonIssuedAt        = "issued_at"
	reasonIdentifier      = "identifier"
	reasonReplay          = "replay"
	reasonRegistry        = "registry_unavailable"
)

// rejection is a stateless validation failure. Its reason goes to the log,
// never into a response.
type rejection struct{ reason string }

func (r *rejection) Error() string { return "client assertion rejected" }

func reject(reason string) error { return &rejection{reason: reason} }

func rejectionReason(err error) string {
	var rejected *rejection
	if errors.As(err, &rejected) {
		return rejected.reason
	}
	return reasonStructure
}

// registeredKey is one public key of a JWK Set. key is nil for an entry that
// can never verify an assertion: a private or symmetric key, an unknown key
// type, or malformed key material.
type registeredKey struct {
	id        string
	use       string
	algorithm string
	curve     string
	key       any
}

// verifies reports whether the key may verify a signature made with the
// given algorithm.
func (k registeredKey) verifies(algorithm string) bool {
	if k.key == nil {
		return false
	}
	if k.use != "" && k.use != "sig" {
		return false
	}
	if k.algorithm != "" && k.algorithm != algorithm {
		return false
	}
	switch algorithm {
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		public, ok := k.key.(*rsa.PublicKey)
		return ok && public.N.BitLen() >= minRsaModulusBits
	case "ES256":
		return k.curve == "P-256"
	case "ES384":
		return k.curve == "P-384"
	case "ES512":
		return k.curve == "P-521"
	default:
		return false
	}
}

// selectKey returns the single registered key that may verify a signature
// made with algorithm and, when keyId is given, carries that key id.
func selectKey(keys []registeredKey, algorithm string, keyId string) (any, error) {
	var found any
	count := 0
	for _, key := range keys {
		if keyId != "" && key.id != keyId {
			continue
		}
		if !key.verifies(algorithm) {
			continue
		}
		found = key.key
		count++
	}
	switch count {
	case 0:
		return nil, reject(reasonKeyNotFound)
	case 1:
		return found, nil
	default:
		return nil, reject(reasonKeyAmbiguous)
	}
}

// jwkMembers holds the JWK members this package reads.
type jwkMembers struct {
	KeyType   string          `json:"kty"`
	KeyId     string          `json:"kid"`
	Use       string          `json:"use"`
	Algorithm string          `json:"alg"`
	Modulus   string          `json:"n"`
	Exponent  string          `json:"e"`
	Curve     string          `json:"crv"`
	X         string          `json:"x"`
	Y         string          `json:"y"`
	Private   json.RawMessage `json:"d"`
	Symmetric json.RawMessage `json:"k"`
}

// parseKeySet reads a JWK Set document. With allowSingleKey a single JWK is
// read as a set of one. A document that is not a JWK Set, or an empty set, is
// an error; a member that cannot be read stays in the set as unusable.
func parseKeySet(document []byte, allowSingleKey bool) ([]registeredKey, error) {
	var set struct {
		Keys *[]json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(document, &set); err != nil {
		return nil, err
	}
	var members []json.RawMessage
	switch {
	case set.Keys != nil:
		members = *set.Keys
	case allowSingleKey:
		members = []json.RawMessage{document}
	default:
		return nil, errors.New("not a JWK Set")
	}
	if len(members) == 0 {
		return nil, errors.New("empty JWK Set")
	}
	keys := make([]registeredKey, 0, len(members))
	for _, member := range members {
		keys = append(keys, readKey(member))
	}
	return keys, nil
}

func readKey(member json.RawMessage) registeredKey {
	var jwk jwkMembers
	if err := json.Unmarshal(member, &jwk); err != nil {
		return registeredKey{}
	}
	key := registeredKey{id: jwk.KeyId, use: jwk.Use, algorithm: jwk.Algorithm}
	if len(jwk.Private) > 0 || len(jwk.Symmetric) > 0 {
		return key
	}
	switch jwk.KeyType {
	case "RSA":
		modulus, err := base64.RawURLEncoding.DecodeString(jwk.Modulus)
		if err != nil || len(modulus) == 0 {
			return key
		}
		exponent, err := base64.RawURLEncoding.DecodeString(jwk.Exponent)
		if err != nil || len(exponent) == 0 || len(exponent) > 4 {
			return key
		}
		e := new(big.Int).SetBytes(exponent).Int64()
		if e < 3 || e&1 == 0 || e > 1<<31-1 {
			return key
		}
		key.key = &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: int(e)}
	case "EC":
		var curve elliptic.Curve
		switch jwk.Curve {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return key
		}
		x, err := base64.RawURLEncoding.DecodeString(jwk.X)
		if err != nil {
			return key
		}
		y, err := base64.RawURLEncoding.DecodeString(jwk.Y)
		if err != nil {
			return key
		}
		size := (curve.Params().BitSize + 7) / 8
		if len(x) != size || len(y) != size {
			return key
		}
		point := make([]byte, 0, 1+2*size)
		point = append(point, 4)
		point = append(point, x...)
		point = append(point, y...)
		public, err := ecdsa.ParseUncompressedPublicKey(curve, point)
		if err != nil {
			return key
		}
		key.curve = jwk.Curve
		key.key = public
	}
	return key
}

// jwksEntry is the cached state of one JWK Set address.
type jwksEntry struct {
	keys []registeredKey
	// fetchedAt is the time of the last successful fetch; zero when the
	// address was never fetched successfully.
	fetchedAt time.Time
	// attemptedAt is the time of the last fetch attempt.
	attemptedAt time.Time
	// inflight is the fetch in progress, shared by every caller that needs
	// this address while it runs.
	inflight *jwksFetch
}

type jwksFetch struct {
	done chan struct{}
	keys []registeredKey
	err  error
}

// KeySource supplies the registered public keys of a principal: it reads an
// inline JWK Set, or fetches the pre-registered JWK Set address and keeps the
// result in memory. The cache can be rebuilt at any time; it is the only
// state the key source holds.
type KeySource struct {
	options func() Options
	clock   services.SystemClock
	logger  *slog.Logger

	transportOnce sync.Once
	transport     http.RoundTripper

	mu      sync.Mutex
	entries map[string]*jwksEntry
}

// NewKeySource returns a key source. options is read on every use, so a key
// source built before the feature is configured sees the final options.
func NewKeySource(options func() Options, clock services.SystemClock, logger *slog.Logger) *KeySource {
	return &KeySource{options: options, clock: clock, logger: logger, entries: make(map[string]*jwksEntry)}
}

// verificationKey returns the single public key registered for the principal
// that may verify a signature made with algorithm under keyId.
func (s *KeySource) verificationKey(ctx context.Context, principal Principal, algorithm string, keyId string) (any, error) {
	options := currentOptions(s.options)
	switch {
	case principal.Jwks != "" && principal.JwksUri != "":
		return nil, reject(reasonKeyRegistration)
	case principal.Jwks != "":
		keys, err := parseKeySet([]byte(principal.Jwks), false)
		if err != nil {
			return nil, reject(reasonKeyRegistration)
		}
		return selectKey(keys, algorithm, keyId)
	case principal.JwksUri != "":
		return s.fetchedKey(ctx, options, principal, algorithm, keyId)
	default:
		return nil, reject(reasonKeyRegistration)
	}
}

func (s *KeySource) fetchedKey(ctx context.Context, options Options, principal Principal, algorithm string, keyId string) (any, error) {
	address, err := url.Parse(principal.JwksUri)
	if err != nil || address.Host == "" || !(address.Scheme == "https" || (address.Scheme == "http" && options.AllowInsecureJwksUri)) {
		s.warn(principal, address, "address_not_allowed")
		return nil, reject(reasonKeyRegistration)
	}
	keys, fetched, err := s.keySet(ctx, options, principal, address, false)
	if err != nil {
		return nil, reject(reasonKeyUnavailable)
	}
	key, err := selectKey(keys, algorithm, keyId)
	if err == nil || fetched || keyId == "" || rejectionReason(err) != reasonKeyNotFound {
		return key, err
	}
	// The key id is unknown to the cached set: the principal may have rotated
	// its keys, so the set is fetched once more, within the rate limit.
	keys, fetched, err = s.keySet(ctx, options, principal, address, true)
	if err != nil || !fetched {
		return nil, reject(reasonKeyNotFound)
	}
	return selectKey(keys, algorithm, keyId)
}

// keySet returns the key set of a JWK Set address and whether this call
// fetched it or shared a fetch in progress. Without refresh a cached set that
// is still within its lifetime is returned as is. Any fetch, the first one
// included, happens at most once per minimum refresh interval for an
// address; a caller that may not fetch gets the cached set when it is still
// usable and an error otherwise.
func (s *KeySource) keySet(ctx context.Context, options Options, principal Principal, address *url.URL, refresh bool) ([]registeredKey, bool, error) {
	uri := principal.JwksUri
	s.mu.Lock()
	now := s.clock.Now()
	entry := s.entries[uri]
	usable := entry != nil && !entry.fetchedAt.IsZero() && now.Sub(entry.fetchedAt) <= options.JwksCacheLifetime
	if usable && !refresh {
		keys := entry.keys
		s.mu.Unlock()
		return keys, false, nil
	}
	if entry != nil && entry.inflight != nil {
		fetch := entry.inflight
		s.mu.Unlock()
		select {
		case <-fetch.done:
			return fetch.keys, true, fetch.err
		case <-ctx.Done():
			return nil, true, ctx.Err()
		}
	}
	if entry != nil && now.Sub(entry.attemptedAt) < options.JwksMinRefreshInterval {
		keys := entry.keys
		s.mu.Unlock()
		if usable {
			return keys, false, nil
		}
		return nil, false, errors.New("JWK Set fetch rate limited")
	}
	if entry == nil {
		entry = &jwksEntry{}
		s.entries[uri] = entry
		s.evictLocked(entry)
	}
	entry.attemptedAt = now
	fetch := &jwksFetch{done: make(chan struct{})}
	entry.inflight = fetch
	s.mu.Unlock()

	keys, category, err := s.fetch(ctx, options, address)

	s.mu.Lock()
	entry.inflight = nil
	if err == nil {
		entry.keys = keys
		entry.fetchedAt = s.clock.Now()
		fetch.keys = keys
	} else {
		fetch.err = err
	}
	s.mu.Unlock()
	close(fetch.done)
	if err != nil {
		s.warn(principal, address, category)
		return nil, true, err
	}
	return keys, true, nil
}

// evictLocked keeps the cache within its bound by dropping the entry whose
// last successful fetch is the oldest. The entry just added and entries with
// a fetch in progress stay.
func (s *KeySource) evictLocked(added *jwksEntry) {
	for len(s.entries) > maxJwksCacheEntries {
		victim := ""
		var oldest *jwksEntry
		for uri, entry := range s.entries {
			if entry == added || entry.inflight != nil {
				continue
			}
			if oldest == nil || entry.fetchedAt.Before(oldest.fetchedAt) ||
				(entry.fetchedAt.Equal(oldest.fetchedAt) && entry.attemptedAt.Before(oldest.attemptedAt)) {
				victim, oldest = uri, entry
			}
		}
		if oldest == nil {
			return
		}
		delete(s.entries, victim)
	}
}

// fetch requests the JWK Set address once. It follows no redirect, accepts
// status 200 only and reads no more than the configured size.
func (s *KeySource) fetch(ctx context.Context, options Options, address *url.URL) ([]registeredKey, string, error) {
	ctx, cancel := context.WithTimeout(ctx, options.JwksFetchTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address.String(), nil)
	if err != nil {
		return nil, "request", err
	}
	client := http.Client{
		Transport: s.transportFor(options),
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	response, err := client.Do(request)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, "timeout", err
		}
		return nil, "transport", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, "status", errors.New("JWK Set address did not answer 200")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, options.MaxJwksResponseBytes+1))
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, "timeout", err
		}
		return nil, "transport", err
	}
	if int64(len(body)) > options.MaxJwksResponseBytes {
		return nil, "too_large", errors.New("JWK Set exceeds the size limit")
	}
	keys, err := parseKeySet(body, false)
	if err != nil {
		return nil, "document", err
	}
	return keys, "", nil
}

func (s *KeySource) transportFor(options Options) http.RoundTripper {
	if options.HTTPClient != nil && options.HTTPClient.Transport != nil {
		return options.HTTPClient.Transport
	}
	s.transportOnce.Do(func() {
		s.transport = &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          16,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
		}
	})
	return s.transport
}

// warn records a failed JWK Set fetch: who it was for, where it went (scheme
// and host only) and what kind of failure it was.
func (s *KeySource) warn(principal Principal, address *url.URL, category string) {
	if s.logger == nil {
		return
	}
	scheme, host := "", ""
	if address != nil {
		scheme, host = strings.ToLower(address.Scheme), address.Host
	}
	s.logger.Warn("client assertion key set could not be fetched",
		slog.String("client_id", principal.ID),
		slog.String("scheme", scheme),
		slog.String("host", host),
		slog.String("category", category))
}
