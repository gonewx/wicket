// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package core

import (
	"encoding/base64"
	"testing"

	"github.com/gonewx/wicket/auth"
	"github.com/gonewx/wicket/dp"
)

type testProtector struct {
	purpose string
}

func (p *testProtector) Create(purpose string) dp.DataProtector {
	return &testProtector{purpose: p.purpose + "." + purpose}
}

func (p *testProtector) Protect(data []byte) []byte {
	tagged := append([]byte(p.purpose+"|"), data...)
	out := make([]byte, base64.RawURLEncoding.EncodedLen(len(tagged)))
	base64.RawURLEncoding.Encode(out, tagged)
	return out
}

func (p *testProtector) Unprotect(data []byte) ([]byte, error) {
	out := make([]byte, base64.RawURLEncoding.DecodedLen(len(data)))
	n, err := base64.RawURLEncoding.Decode(out, data)
	if err != nil {
		return nil, err
	}
	decoded := out[:n]
	for i, b := range decoded {
		if b == '|' {
			return decoded[i+1:], nil
		}
	}
	return decoded, nil
}

type testData struct {
	Name  string `json:"name"`
	Value int    `json:"value"`
}

func TestSecureDataFormatRoundTrip(t *testing.T) {
	t.Parallel()

	protector := &testProtector{purpose: "test"}
	sdf := NewSecureDataFormat[testData](nil, protector)

	original := &testData{Name: "hello", Value: 42}
	protected := sdf.Protect(original)

	if protected == "" {
		t.Fatal("expected non-empty protected text")
	}

	restored := sdf.Unprotect(protected)
	if restored == nil {
		t.Fatal("expected non-nil restored value")
	}
	if restored.Name != "hello" || restored.Value != 42 {
		t.Fatalf("expected {hello, 42}, got {%s, %d}", restored.Name, restored.Value)
	}
}

func TestSecureDataFormatWithPurpose(t *testing.T) {
	t.Parallel()

	protector := &testProtector{purpose: "root"}
	sdf := NewSecureDataFormat[testData](nil, protector)

	original := &testData{Name: "purpose-test", Value: 7}
	p1 := sdf.ProtectWithPurpose(original, "signing")
	p2 := sdf.ProtectWithPurpose(original, "encryption")

	if p1 == p2 {
		t.Fatal("expected different protected values for different purposes")
	}

	r1 := sdf.UnprotectWithPurpose(p1, "signing")
	if r1 == nil || r1.Name != "purpose-test" {
		t.Fatal("expected successful unprotect with matching purpose")
	}
}

func TestSecureDataFormatUnprotectEmptyReturnsNil(t *testing.T) {
	t.Parallel()

	protector := &testProtector{purpose: "test"}
	sdf := NewSecureDataFormat[testData](nil, protector)

	if sdf.Unprotect("") != nil {
		t.Fatal("expected nil for empty input")
	}
	if sdf.Unprotect("   ") != nil {
		t.Fatal("expected nil for whitespace input")
	}
}

func TestSecureDataFormatUnprotectInvalidBase64ReturnsNil(t *testing.T) {
	t.Parallel()

	protector := &testProtector{purpose: "test"}
	sdf := NewSecureDataFormat[testData](nil, protector)

	if sdf.Unprotect("not-valid-base64!!!") != nil {
		t.Fatal("expected nil for invalid base64")
	}
}

// --- PropertiesSerializer tests ---

func TestPropertiesSerializerRoundTrip(t *testing.T) {
	t.Parallel()

	s := NewPropertiesSerializer()
	props := auth.NewProperties()
	props.Items["redirect_uri"] = "https://example.com/callback"
	props.Items["scope"] = "openid profile"

	data := s.Serialize(props)
	if len(data) == 0 {
		t.Fatal("expected non-empty serialized data")
	}

	restored := s.Deserialize(data)
	if restored == nil {
		t.Fatal("expected non-nil deserialized Properties")
	}
	if len(restored.Items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(restored.Items))
	}
	if restored.Items["redirect_uri"] != "https://example.com/callback" {
		t.Fatalf("expected redirect_uri preserved, got %q", restored.Items["redirect_uri"])
	}
	if restored.Items["scope"] != "openid profile" {
		t.Fatalf("expected scope preserved, got %q", restored.Items["scope"])
	}
}

func TestPropertiesSerializerEmptyProperties(t *testing.T) {
	t.Parallel()

	s := NewPropertiesSerializer()
	props := auth.NewProperties()

	data := s.Serialize(props)
	restored := s.Deserialize(data)

	if restored == nil {
		t.Fatal("expected non-nil deserialized Properties")
	}
	if len(restored.Items) != 0 {
		t.Fatalf("expected 0 items, got %d", len(restored.Items))
	}
}

func TestPropertiesSerializerInvalidDataReturnsNil(t *testing.T) {
	t.Parallel()

	s := NewPropertiesSerializer()

	if s.Deserialize(nil) != nil {
		t.Fatal("expected nil for nil data")
	}
	if s.Deserialize([]byte{}) != nil {
		t.Fatal("expected nil for empty data")
	}
	if s.Deserialize([]byte{0, 0, 0, 99}) != nil {
		t.Fatal("expected nil for wrong version")
	}
}
