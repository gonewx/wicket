//go:build integration

// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package di_test

import (
	"testing"

	"github.com/gonewx/wicket/di"
)

func TestKeyManagementResolvesFromContainer(t *testing.T) {
	t.Parallel()

	root, err := di.NewRoot()
	if err != nil {
		t.Fatalf("construct root: %v", err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Fatalf("close root: %v", err)
		}
	})

	manager := root.Ptr_Manager()
	if manager == nil {
		t.Fatal("key manager did not resolve")
	}
	if manager.Enabled() {
		t.Fatal("key manager is enabled by default; it must default to disabled")
	}

	service := root.NewKeyMaterialService()
	if service == nil {
		t.Fatal("KeyMaterialService did not resolve")
	}

	// Disabled default with no host validation stores: an empty, non-error set.
	keys, err := service.GetValidationKeys()
	if err != nil {
		t.Fatalf("validation keys: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("default validation key count = %d, want 0", len(keys))
	}
}
