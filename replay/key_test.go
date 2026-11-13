// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package replay_test

import (
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/gonewx/wicket/replay"
	"github.com/gonewx/wicket/replay/replaytest"
)

var keyShape = regexp.MustCompile(`^[0-9a-f]{64}$`)

func mustKey(t *testing.T, purpose replay.Purpose, qualifier, jti string) string {
	t.Helper()
	key, err := replay.Key(purpose, qualifier, jti)
	if err != nil {
		t.Fatalf("Key(%q, %q) returned %v", qualifier, jti, err)
	}
	return key
}

func TestKeyMatchesSuiteVectors(t *testing.T) {
	vectors := replaytest.KeyVectors()
	if len(vectors) != 6 {
		t.Fatalf("suite provides %d key vectors, want 6", len(vectors))
	}
	for _, vector := range vectors {
		got := mustKey(t, vector.Purpose, vector.Qualifier, vector.JTI)
		if got != vector.Key {
			t.Errorf("%s: Key = %s, want %s", vector.Name, got, vector.Key)
		}
		if !keyShape.MatchString(got) {
			t.Errorf("%s: Key = %q, want 64 lowercase hexadecimal characters", vector.Name, got)
		}
	}
}

// The expected keys are repeated here as literals, so the vector table and
// the key function cannot drift together unnoticed.
func TestKeyMatchesPinnedLiterals(t *testing.T) {
	assertion := replay.PurposeClientAssertion()

	v1 := mustKey(t, assertion, "client-a", "jti-1")
	if want := "d20bdf573a5e70c94195ad2ca9cd1a3920089024cc8e4d02c7d22469e639d59c"; v1 != want {
		t.Errorf("V1: Key = %s, want %s", v1, want)
	}
	v3 := mustKey(t, assertion, "ab", "c")
	if want := "1ed0f1c6edc07cefa06a7be4ca57ab1536abac237d63d3af0800d80176a0d6b8"; v3 != want {
		t.Errorf("V3: Key = %s, want %s", v3, want)
	}
	v4 := mustKey(t, assertion, "a", "bc")
	if want := "872c8ac37fcd66cc458d779d9a111975d2b09287e684d7fd8e93f073094d1e11"; v4 != want {
		t.Errorf("V4: Key = %s, want %s", v4, want)
	}

	// Where qualifier ends and jti begins is part of the key.
	if v3 == v4 {
		t.Errorf(`Key("ab", "c") and Key("a", "bc") are both %s`, v3)
	}
	// So is the purpose.
	if v2 := mustKey(t, replay.PurposeDPoPProof(), "client-a", "jti-1"); v1 == v2 {
		t.Errorf("the two purposes give the same key %s for one qualifier and jti", v1)
	}
}

func TestKeyShapeAndOpaqueInputs(t *testing.T) {
	assertion := replay.PurposeClientAssertion()
	inputs := []struct{ qualifier, jti string }{
		{"c", "j"},
		{"Client-A", "jti-1"},
		{"client-a", "JTI-1"},
		{" client-a", "jti-1"},
		{"client-a", "jti-1 "},
		{"client-a\x00", "jti-1"},
		{"\xff\xfe", "\x80"},
		{strings.Repeat("q", 4096), strings.Repeat("j", 4096)},
	}

	seen := map[string]int{mustKey(t, assertion, "client-a", "jti-1"): -1}
	for i, input := range inputs {
		key := mustKey(t, assertion, input.qualifier, input.jti)
		if !keyShape.MatchString(key) {
			t.Errorf("input %d: Key = %q, want 64 lowercase hexadecimal characters", i, key)
		}
		// Nothing is trimmed, case-folded or normalized, so every input
		// here has a key of its own.
		if other, dup := seen[key]; dup {
			t.Errorf("inputs %d and %d give the same key", other, i)
		}
		seen[key] = i
		if again := mustKey(t, assertion, input.qualifier, input.jti); again != key {
			t.Errorf("input %d: Key is not stable: %s then %s", i, key, again)
		}
	}
}

func TestKeyRejectsInvalidInput(t *testing.T) {
	cases := []struct {
		name           string
		purpose        replay.Purpose
		qualifier, jti string
	}{
		{"zero purpose", replay.Purpose{}, "client-a", "jti-1"},
		{"empty qualifier", replay.PurposeClientAssertion(), "", "jti-1"},
		{"empty jti", replay.PurposeDPoPProof(), "client-a", ""},
		{"everything empty", replay.Purpose{}, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			key, err := replay.Key(c.purpose, c.qualifier, c.jti)
			if !errors.Is(err, replay.ErrInvalidKeyInput) {
				t.Fatalf("Key returned error %v, want one matching replay.ErrInvalidKeyInput", err)
			}
			if key != "" {
				t.Fatalf("Key returned %q alongside an error, want an empty key", key)
			}
		})
	}
}

// An error from Key says what was wrong without repeating the values, on
// each of the three ways the input can be rejected.
func TestKeyErrorOmitsInputValues(t *testing.T) {
	const qualifier, jti = "qualifier-value-7c1d", "jti-value-93ab"

	cases := []struct {
		name           string
		purpose        replay.Purpose
		qualifier, jti string
	}{
		{"zero purpose", replay.Purpose{}, qualifier, jti},
		{"empty qualifier", replay.PurposeClientAssertion(), "", jti},
		{"empty jti", replay.PurposeDPoPProof(), qualifier, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := replay.Key(c.purpose, c.qualifier, c.jti)
			if err == nil {
				t.Fatal("Key accepted the input")
			}
			if text := err.Error(); strings.Contains(text, qualifier) || strings.Contains(text, jti) {
				t.Fatalf("error text %q repeats an input value", text)
			}
		})
	}
}

func TestPurposeValues(t *testing.T) {
	if replay.PurposeClientAssertion() == replay.PurposeDPoPProof() {
		t.Fatal("the two purposes are equal")
	}
	if replay.PurposeClientAssertion() != replay.PurposeClientAssertion() {
		t.Fatal("PurposeClientAssertion() is not equal to itself across calls")
	}
	if replay.PurposeDPoPProof() != replay.PurposeDPoPProof() {
		t.Fatal("PurposeDPoPProof() is not equal to itself across calls")
	}
	var zero replay.Purpose
	if zero == replay.PurposeClientAssertion() || zero == replay.PurposeDPoPProof() {
		t.Fatal("the zero Purpose equals a defined purpose")
	}
}

func TestErrorValuesAreDistinct(t *testing.T) {
	values := []error{replay.ErrDuplicateHandle, replay.ErrInvalidArgument, replay.ErrInvalidKeyInput}
	texts := []string{"replay: duplicate handle", "replay: invalid argument", "replay: invalid key input"}
	for i, value := range values {
		if value.Error() != texts[i] {
			t.Errorf("error %d reads %q, want %q", i, value.Error(), texts[i])
		}
		for j, other := range values {
			if i != j && errors.Is(value, other) {
				t.Errorf("%q matches %q", value, other)
			}
		}
	}
}
