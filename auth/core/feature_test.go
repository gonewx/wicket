// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package core

import (
	"context"
	"testing"
)

func TestFeatureGettersAndSetters(t *testing.T) {
	t.Parallel()

	f := NewFeature()

	if f.OriginalPathBase() != "" {
		t.Fatal("expected empty OriginalPathBase initially")
	}
	if f.OriginalPath() != "" {
		t.Fatal("expected empty OriginalPath initially")
	}

	f.SetOriginalPathBase("/api")
	f.SetOriginalPath("/users")

	if f.OriginalPathBase() != "/api" {
		t.Fatalf("expected %q, got %q", "/api", f.OriginalPathBase())
	}
	if f.OriginalPath() != "/users" {
		t.Fatalf("expected %q, got %q", "/users", f.OriginalPath())
	}
}

func TestContextWithFeatureRoundTrip(t *testing.T) {
	t.Parallel()

	f := NewFeature()
	f.SetOriginalPath("/test")

	ctx := ContextWithFeature(context.Background(), f)
	got := FeatureFrom(ctx)

	if got == nil {
		t.Fatal("expected feature from context")
	}
	if got.OriginalPath() != "/test" {
		t.Fatalf("expected %q, got %q", "/test", got.OriginalPath())
	}
}

func TestFeatureFromEmptyContext(t *testing.T) {
	t.Parallel()

	got := FeatureFrom(context.Background())
	if got != nil {
		t.Fatal("expected nil when no feature in context")
	}
}
