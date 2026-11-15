// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package dpop

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

const testSurface = "authorization-server https://as.example"

func testNonceKey(id string, fill byte) NonceKey {
	return NonceKey{Id: id, Secret: bytes.Repeat([]byte{fill}, 32)}
}

func staticKeys(t *testing.T, current NonceKey, previous ...NonceKey) NonceKeySource {
	t.Helper()
	source, err := NewStaticNonceKeys(current, previous...)
	if err != nil {
		t.Fatal(err)
	}
	return source
}

var nonceTestOptions = Options{NonceLifetime: 5 * time.Minute, ClockSkew: 30 * time.Second}

func issue(t *testing.T, sealer *NonceSealer, surface string, at time.Time) string {
	t.Helper()
	nonce, err := sealer.Issue(surface, at)
	if err != nil {
		t.Fatal(err)
	}
	return nonce
}

func TestNonceRoundTripAndWindow(t *testing.T) {
	t.Parallel()
	sealer := NewNonceSealer(staticKeys(t, testNonceKey("k1", 1)), nonceTestOptions)
	nonce := issue(t, sealer, testSurface, testNow)
	if len(nonce) > maxNonceEncodedLength {
		t.Fatalf("nonce %d characters", len(nonce))
	}
	cases := map[string]struct {
		at    time.Time
		valid bool
	}{
		"at issue":                     {testNow, true},
		"last accepted instant":        {testNow.Add(5*time.Minute + 30*time.Second), true},
		"one second after the window":  {testNow.Add(5*time.Minute + 31*time.Second), false},
		"issued within the clock skew": {testNow.Add(-30 * time.Second), true},
		"issued beyond the clock skew": {testNow.Add(-31 * time.Second), false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			deadline, err := sealer.Check(nonce, testSurface, tc.at)
			if tc.valid {
				if err != nil {
					t.Fatalf("check: %v", err)
				}
				if !deadline.Equal(testNow.Add(5 * time.Minute)) {
					t.Fatalf("deadline %s", deadline)
				}
				return
			}
			if !errors.Is(err, ErrInvalidNonce) {
				t.Fatalf("err %v, want ErrInvalidNonce", err)
			}
		})
	}
}

func TestNonceDefaultsApply(t *testing.T) {
	t.Parallel()
	sealer := NewNonceSealer(staticKeys(t, testNonceKey("k1", 1)), Options{})
	nonce := issue(t, sealer, testSurface, testNow)
	deadline, err := sealer.Check(nonce, testSurface, testNow)
	if err != nil || !deadline.Equal(testNow.Add(5*time.Minute)) {
		t.Fatalf("deadline %s err %v", deadline, err)
	}
	if _, err := sealer.Check(nonce, testSurface, testNow.Add(6*time.Minute+time.Second)); !errors.Is(err, ErrInvalidNonce) {
		t.Fatalf("beyond default lifetime and skew: %v", err)
	}
}

func TestNonceRefusals(t *testing.T) {
	t.Parallel()
	sealer := NewNonceSealer(staticKeys(t, testNonceKey("k1", 1)), nonceTestOptions)
	nonce := issue(t, sealer, testSurface, testNow)
	raw, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil {
		t.Fatal(err)
	}
	encode := base64.RawURLEncoding.EncodeToString
	flip := func(index int) string {
		changed := bytes.Clone(raw)
		changed[index] ^= 0x01
		return encode(changed)
	}
	other := NewNonceSealer(staticKeys(t, testNonceKey("k2", 2)), nonceTestOptions)
	sameIdOtherSecret := NewNonceSealer(staticKeys(t, testNonceKey("k1", 9)), nonceTestOptions)

	cases := map[string]struct {
		nonce   string
		surface string
	}{
		"empty":                {"", testSurface},
		"too long":             {strings.Repeat("A", maxNonceEncodedLength+1), testSurface},
		"not base64url":        {nonce[:10] + "*" + nonce[11:], testSurface},
		"padded":               {nonce + "=", testSurface},
		"truncated":            {encode(raw[:len(raw)-1]), testSurface},
		"extended":             {encode(append(bytes.Clone(raw), 0)), testSurface},
		"wrong version":        {flip(0), testSurface},
		"changed issue time":   {flip(8), testSurface},
		"changed id length":    {flip(9), testSurface},
		"changed mac":          {flip(len(raw) - 1), testSurface},
		"other surface":        {nonce, "authorization-server https://other.example"},
		"unknown key id":       {issue(t, other, testSurface, testNow), testSurface},
		"same id other secret": {issue(t, sameIdOtherSecret, testSurface, testNow), testSurface},
		"zero id length":       {encode(append(append([]byte{nonceVersion}, raw[1:9]...), append([]byte{0}, make([]byte, nonceMacBytes)...)...)), testSurface},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := sealer.Check(tc.nonce, tc.surface, testNow); !errors.Is(err, ErrInvalidNonce) {
				t.Fatalf("err %v, want ErrInvalidNonce", err)
			}
		})
	}
}

func TestNonceLongestKeyIdRoundTrips(t *testing.T) {
	t.Parallel()
	id := strings.Repeat("a", maxNonceKeyIdBytes)
	sealer := NewNonceSealer(staticKeys(t, testNonceKey(id, 1)), nonceTestOptions)
	nonce := issue(t, sealer, testSurface, testNow)
	if len(nonce) != 99 {
		t.Fatalf("longest nonce has %d characters, want 99", len(nonce))
	}
	if _, err := sealer.Check(nonce, testSurface, testNow); err != nil {
		t.Fatalf("check: %v", err)
	}
}

func TestNonceRotation(t *testing.T) {
	t.Parallel()
	old := testNonceKey("old", 1)
	next := testNonceKey("next", 2)
	before := NewNonceSealer(staticKeys(t, old), nonceTestOptions)
	staged := NewNonceSealer(staticKeys(t, old, next), nonceTestOptions)
	after := NewNonceSealer(staticKeys(t, next, old), nonceTestOptions)
	retired := NewNonceSealer(staticKeys(t, next), nonceTestOptions)

	byOld := issue(t, before, testSurface, testNow)
	if _, err := staged.Check(byOld, testSurface, testNow); err != nil {
		t.Fatalf("staged replica refuses current nonce: %v", err)
	}
	byNext := issue(t, after, testSurface, testNow)
	if _, err := staged.Check(byNext, testSurface, testNow); err != nil {
		t.Fatalf("staged replica refuses the next key: %v", err)
	}
	if _, err := after.Check(byOld, testSurface, testNow); err != nil {
		t.Fatalf("previous key refused: %v", err)
	}
	if _, err := retired.Check(byOld, testSurface, testNow); !errors.Is(err, ErrInvalidNonce) {
		t.Fatalf("removed key still accepted: %v", err)
	}
}

func TestNonceSealersSharingASourceAgree(t *testing.T) {
	t.Parallel()
	source := staticKeys(t, testNonceKey("k1", 1))
	a := NewNonceSealer(source, nonceTestOptions)
	b := NewNonceSealer(source, nonceTestOptions)
	if _, err := b.Check(issue(t, a, testSurface, testNow), testSurface, testNow.Add(time.Minute)); err != nil {
		t.Fatalf("replica refuses: %v", err)
	}
}

type nonceSourceFunc func() (NonceKey, []NonceKey, error)

func (f nonceSourceFunc) NonceKeys() (NonceKey, []NonceKey, error) { return f() }

func TestNonceKeySourceFailures(t *testing.T) {
	t.Parallel()
	good := NewNonceSealer(staticKeys(t, testNonceKey("k1", 1)), nonceTestOptions)
	nonce := issue(t, good, testSurface, testNow)
	sourceErr := errors.New("source down")
	cases := map[string]*NonceSealer{
		"source error": NewNonceSealer(nonceSourceFunc(func() (NonceKey, []NonceKey, error) {
			return NonceKey{}, nil, sourceErr
		}), nonceTestOptions),
		"invalid keys": NewNonceSealer(nonceSourceFunc(func() (NonceKey, []NonceKey, error) {
			return NonceKey{Id: "k1", Secret: []byte("short")}, nil, nil
		}), nonceTestOptions),
		"nil source": NewNonceSealer(nil, nonceTestOptions),
	}
	for name, sealer := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := sealer.Issue(testSurface, testNow); err == nil || errors.Is(err, ErrInvalidNonce) {
				t.Fatalf("issue: %v", err)
			}
			if _, err := sealer.Check(nonce, testSurface, testNow); err == nil || errors.Is(err, ErrInvalidNonce) {
				t.Fatalf("check: %v", err)
			}
		})
	}
	if _, err := good.Issue("", testNow); err == nil {
		t.Fatal("empty surface issued")
	}
	if _, err := good.Check(nonce, "", testNow); err == nil || errors.Is(err, ErrInvalidNonce) {
		t.Fatalf("empty surface checked: %v", err)
	}
}

func TestValidateNonceKeys(t *testing.T) {
	t.Parallel()
	good := testNonceKey("k1", 1)
	cases := map[string]struct {
		current  NonceKey
		previous []NonceKey
		valid    bool
	}{
		"valid":                {good, []NonceKey{testNonceKey("k2", 2)}, true},
		"all id characters":    {testNonceKey("Az09._-", 1), nil, true},
		"longest id":           {testNonceKey(strings.Repeat("x", 32), 1), nil, true},
		"short secret":         {NonceKey{Id: "k1", Secret: make([]byte, 31)}, nil, false},
		"empty id":             {testNonceKey("", 1), nil, false},
		"long id":              {testNonceKey(strings.Repeat("x", 33), 1), nil, false},
		"id with space":        {testNonceKey("k 1", 1), nil, false},
		"id with slash":        {testNonceKey("k/1", 1), nil, false},
		"id not ascii":         {testNonceKey("kä", 1), nil, false},
		"duplicate id":         {good, []NonceKey{testNonceKey("k1", 2)}, false},
		"invalid previous key": {good, []NonceKey{{Id: "k2"}}, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := ValidateNonceKeys(tc.current, tc.previous)
			if tc.valid != (err == nil) {
				t.Fatalf("err %v, want valid %v", err, tc.valid)
			}
			_, err = NewStaticNonceKeys(tc.current, tc.previous...)
			if tc.valid != (err == nil) {
				t.Fatalf("NewStaticNonceKeys err %v, want valid %v", err, tc.valid)
			}
		})
	}
}

func TestStaticNonceKeysAreCopies(t *testing.T) {
	t.Parallel()
	key := testNonceKey("k1", 1)
	source := staticKeys(t, key)
	key.Secret[0] = 0xff
	current, _, err := source.NonceKeys()
	if err != nil || current.Secret[0] != 1 {
		t.Fatalf("source shares the caller's secret: %v %v", current.Secret[0], err)
	}
	current.Secret[1] = 0xff
	again, _, _ := source.NonceKeys()
	if again.Secret[1] != 1 {
		t.Fatal("source hands out its own secret")
	}
}
