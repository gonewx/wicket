// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package replaytest

import (
	"regexp"
	"testing"

	"github.com/gonewx/wicket/replay"
)

var keyShape = regexp.MustCompile(`^[0-9a-f]{64}$`)

func TestSuiteVersionIsVersionedOnItsOwn(t *testing.T) {
	if SuiteVersion != "1.0.0" {
		t.Fatalf("SuiteVersion = %q, want %q", SuiteVersion, "1.0.0")
	}
}

func TestKeyVectorsTable(t *testing.T) {
	vectors := KeyVectors()
	wantNames := []string{"V1", "V2", "V3", "V4", "V5", "V6"}
	if len(vectors) != len(wantNames) {
		t.Fatalf("KeyVectors() has %d vectors, want %d", len(vectors), len(wantNames))
	}

	seen := map[string]string{}
	for i, vector := range vectors {
		if vector.Name != wantNames[i] {
			t.Errorf("vector %d is named %q, want %q", i, vector.Name, wantNames[i])
		}
		if !keyShape.MatchString(vector.Key) {
			t.Errorf("%s: key %q is not 64 lowercase hexadecimal characters", vector.Name, vector.Key)
		}
		if vector.Purpose != replay.PurposeClientAssertion() && vector.Purpose != replay.PurposeDPoPProof() {
			t.Errorf("%s: purpose is not one of the two defined purposes", vector.Name)
		}
		if vector.Qualifier == "" || vector.JTI == "" {
			t.Errorf("%s: qualifier and jti must not be empty", vector.Name)
		}
		if other, dup := seen[vector.Key]; dup {
			t.Errorf("%s and %s share a key", other, vector.Name)
		}
		seen[vector.Key] = vector.Name
	}

	// The qualifier of V5 is nine bytes: the last character takes two.
	if got := len(vectors[4].Qualifier); got != 9 {
		t.Errorf("V5 qualifier is %d bytes, want 9", got)
	}
}

func TestKeyVectorsReturnsNewSlice(t *testing.T) {
	first := KeyVectors()
	first[0].Key = "changed"
	first[0].Name = "changed"
	if second := KeyVectors(); second[0].Name != "V1" || !keyShape.MatchString(second[0].Key) {
		t.Fatalf("a change to one result of KeyVectors() shows in the next: %+v", second[0])
	}
}

func TestKeyVectorsAgreeWithKey(t *testing.T) {
	for _, vector := range KeyVectors() {
		got, err := replay.Key(vector.Purpose, vector.Qualifier, vector.JTI)
		if err != nil {
			t.Fatalf("%s: replay.Key returned %v", vector.Name, err)
		}
		if got != vector.Key {
			t.Errorf("%s: replay.Key = %s, want %s", vector.Name, got, vector.Key)
		}
	}
}
