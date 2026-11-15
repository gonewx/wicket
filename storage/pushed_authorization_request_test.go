// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package storage

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/gonewx/wicket/dp"
)

var pushedAuthorizationKeyPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

func TestPushedAuthorizationRequestKey(t *testing.T) {
	t.Parallel()

	first := PushedAuthorizationRequestURIPrefix + "first"
	second := PushedAuthorizationRequestURIPrefix + "second"
	keyFirst, err := PushedAuthorizationRequestKey(first)
	if err != nil {
		t.Fatalf("key(first): %v", err)
	}
	again, err := PushedAuthorizationRequestKey(first)
	if err != nil {
		t.Fatalf("key(first) again: %v", err)
	}
	keySecond, err := PushedAuthorizationRequestKey(second)
	if err != nil {
		t.Fatalf("key(second): %v", err)
	}
	for _, key := range []string{keyFirst, keySecond} {
		if !pushedAuthorizationKeyPattern.MatchString(key) {
			t.Fatalf("key %q is not 43 base64url characters", key)
		}
	}
	if keyFirst != again {
		t.Fatalf("key is not deterministic: %q then %q", keyFirst, again)
	}
	if keyFirst == keySecond {
		t.Fatalf("different request_uris share key %q", keyFirst)
	}
	if keyFirst == first || strings.Contains(keyFirst, "first") {
		t.Fatalf("key %q exposes the request_uri", keyFirst)
	}
	sum := sha256.Sum256([]byte(first))
	if want := base64.RawURLEncoding.EncodeToString(sum[:]); keyFirst != want {
		t.Fatalf("key = %q, want base64url(sha256(full URN)) %q", keyFirst, want)
	}
}

func TestPushedAuthorizationRequestKeyRejectsInvalidURI(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"empty":       "",
		"no prefix":   "abcdef",
		"prefix only": PushedAuthorizationRequestURIPrefix,
		"other urn":   "urn:example:request_uri:abc",
	}
	for name, uri := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			key, err := PushedAuthorizationRequestKey(uri)
			if key != "" || !errors.Is(err, ErrInvalidRequestURI) {
				t.Fatalf("key(%q) = %q, %v; want \"\", ErrInvalidRequestURI", uri, key, err)
			}
		})
	}
	for _, other := range []error{ErrNotFound, ErrDuplicateHandle, ErrVersionConflict, ErrInvalidClientConfiguration} {
		if errors.Is(ErrInvalidRequestURI, other) {
			t.Fatalf("ErrInvalidRequestURI matches %v", other)
		}
	}
}

func TestNewPushedAuthorizationRequestURI(t *testing.T) {
	t.Parallel()

	first, err := NewPushedAuthorizationRequestURI()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	second, err := NewPushedAuthorizationRequestURI()
	if err != nil {
		t.Fatalf("generate again: %v", err)
	}
	if first == second {
		t.Fatalf("two generated handles are equal: %q", first)
	}
	for _, uri := range []string{first, second} {
		suffix, ok := strings.CutPrefix(uri, PushedAuthorizationRequestURIPrefix)
		if !ok {
			t.Fatalf("handle %q lacks the prefix", uri)
		}
		raw, err := base64.RawURLEncoding.DecodeString(suffix)
		if err != nil || len(raw) != 32 {
			t.Fatalf("handle suffix %q is not 32 bytes of base64url: %v", suffix, err)
		}
		if _, err := PushedAuthorizationRequestKey(uri); err != nil {
			t.Fatalf("generated handle %q rejected by the key function: %v", uri, err)
		}
	}

	fixed, err := newPushedAuthorizationRequestURI(bytes.NewReader(bytes.Repeat([]byte{0xab}, 32)))
	if err != nil {
		t.Fatalf("generate from fixed source: %v", err)
	}
	if want := PushedAuthorizationRequestURIPrefix + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xab}, 32)); fixed != want {
		t.Fatalf("handle = %q, want %q", fixed, want)
	}
}

type failingReader struct{ err error }

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }

func TestNewPushedAuthorizationRequestURIFailsWithEntropy(t *testing.T) {
	t.Parallel()

	sourceErr := errors.New("entropy exhausted")
	tests := map[string]func() (string, error){
		"failing source": func() (string, error) { return newPushedAuthorizationRequestURI(failingReader{err: sourceErr}) },
		"short source":   func() (string, error) { return newPushedAuthorizationRequestURI(bytes.NewReader(make([]byte, 31))) },
	}
	for name, generate := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			uri, err := generate()
			if err == nil || uri != "" {
				t.Fatalf("generate = %q, %v; want \"\" and an error", uri, err)
			}
		})
	}
	if _, err := newPushedAuthorizationRequestURI(failingReader{err: sourceErr}); !errors.Is(err, sourceErr) {
		t.Fatalf("error = %v, want it to wrap the source error", err)
	}
}

// xorProtector is a test protector unrelated to the default provider:
// it flips every byte, and Unprotect rejects input that does not carry its
// trailing marker.
type xorProtector struct{ mask byte }

const xorMarker = 0x5a

func (p xorProtector) Create(string) dp.DataProtector { return p }

func (p xorProtector) Protect(data []byte) []byte {
	out := make([]byte, len(data)+1)
	for i, b := range data {
		out[i] = b ^ p.mask
	}
	out[len(data)] = xorMarker
	return out
}

func (p xorProtector) Unprotect(data []byte) ([]byte, error) {
	if len(data) == 0 || data[len(data)-1] != xorMarker {
		return nil, errors.New("xor protector: not protected by this protector")
	}
	out := make([]byte, len(data)-1)
	for i, b := range data[:len(data)-1] {
		out[i] = b ^ p.mask
	}
	return out, nil
}

func pushedAuthorizationTestParameters() url.Values {
	return url.Values{
		"client_id":     {"client-a"},
		"redirect_uri":  {"https://client.example/callback"},
		"scope":         {"openid profile"},
		"resource":      {"https://api.example/one", "https://api.example/two"},
		"response_type": {"code"},
	}
}

func TestPushedAuthorizationParametersRoundTrip(t *testing.T) {
	t.Parallel()

	protector := xorProtector{mask: 0xa5}
	parameters := pushedAuthorizationTestParameters()
	payload, err := ProtectPushedAuthorizationParameters(protector, parameters)
	if err != nil {
		t.Fatalf("protect: %v", err)
	}
	for _, plain := range []string{"client-a", "client.example", "openid", "api.example", "redirect_uri"} {
		if bytes.Contains(payload, []byte(plain)) {
			t.Fatalf("payload carries plaintext %q: %s", plain, payload)
		}
	}
	var container map[string]any
	if err := json.Unmarshal(payload, &container); err != nil {
		t.Fatalf("payload is not a JSON container: %v", err)
	}
	if container["version"] != float64(1) || container["data_protected"] != true {
		t.Fatalf("container = %v, want version 1 and data_protected true", container)
	}
	got, err := UnprotectPushedAuthorizationParameters(protector, payload)
	if err != nil {
		t.Fatalf("unprotect: %v", err)
	}
	if !reflect.DeepEqual(got, parameters) {
		t.Fatalf("round trip = %v, want %v", got, parameters)
	}
}

func TestPushedAuthorizationParametersRejectsBadInput(t *testing.T) {
	t.Parallel()

	protector := xorProtector{mask: 0xa5}
	payload, err := ProtectPushedAuthorizationParameters(protector, pushedAuthorizationTestParameters())
	if err != nil {
		t.Fatalf("protect: %v", err)
	}
	var container pushedAuthorizationPayload
	if err := json.Unmarshal(payload, &container); err != nil {
		t.Fatalf("decode container: %v", err)
	}
	reencode := func(mutate func(*pushedAuthorizationPayload)) []byte {
		c := container
		c.Payload = append([]byte(nil), container.Payload...)
		mutate(&c)
		data, err := json.Marshal(c)
		if err != nil {
			t.Fatalf("encode container: %v", err)
		}
		return data
	}

	if _, err := ProtectPushedAuthorizationParameters(nil, url.Values{}); err == nil {
		t.Fatal("protect with a nil protector succeeded")
	}

	tests := map[string]struct {
		protector dp.DataProtector
		payload   []byte
	}{
		"nil protector":       {protector: nil, payload: payload},
		"unknown version":     {protector: protector, payload: reencode(func(c *pushedAuthorizationPayload) { c.Version = 2 })},
		"zero version":        {protector: protector, payload: reencode(func(c *pushedAuthorizationPayload) { c.Version = 0 })},
		"not data protected":  {protector: protector, payload: reencode(func(c *pushedAuthorizationPayload) { c.DataProtected = false })},
		"corrupt container":   {protector: protector, payload: payload[:len(payload)/2]},
		"empty payload":       {protector: protector, payload: nil},
		"tampered protection": {protector: protector, payload: reencode(func(c *pushedAuthorizationPayload) { c.Payload[len(c.Payload)-1] ^= 0xff })},
		"tampered content":    {protector: protector, payload: reencode(func(c *pushedAuthorizationPayload) { c.Payload[0] ^= 0xff })},
		"other protector":     {protector: xorProtector{mask: 0x11}, payload: payload},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := UnprotectPushedAuthorizationParameters(tc.protector, tc.payload)
			if err == nil {
				t.Fatalf("unprotect = %v, want an error", got)
			}
			if got != nil {
				t.Fatalf("unprotect returned parameters %v alongside error %v", got, err)
			}
		})
	}
}
