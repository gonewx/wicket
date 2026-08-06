//go:build integration

// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package di_test

import (
	"context"
	"testing"
	"time"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket/di"
	"github.com/gonewx/wicket/session"
)

func TestSessionServicesResolveFromContainer(t *testing.T) {
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

	store := godi.GetRequired[session.Store](root)
	if store == nil {
		t.Fatal("session store did not resolve")
	}

	coord := root.NewSessionCoordinationService()
	if coord == nil {
		t.Fatal("session coordination service did not resolve")
	}

	valid, err := coord.ValidateSession(context.Background(), nil)
	if err != nil {
		t.Fatalf("ValidateSession error: %v", err)
	}
	if !valid {
		t.Fatal("ValidateSession should return true when disabled (default)")
	}
}

func TestSessionStoreRoundTrip(t *testing.T) {
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

	store := godi.GetRequired[session.Store](root)
	if store == nil {
		t.Fatal("session store did not resolve")
	}

	clock := root.SystemClock()

	rec := &session.Record{
		SessionID: "integration-test-session",
		SubjectID: "integration-test-user",
		Created:   clock.Now(),
		Renewed:   clock.Now(),
		Expires:   clock.Now().Add(24 * time.Hour),
	}
	if err := store.CreateSession(context.Background(), rec); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	got, err := store.GetSession(context.Background(), "integration-test-session")
	if err != nil || got == nil {
		t.Fatalf("GetSession: got=%v, err=%v", got, err)
	}
	if got.SubjectID != "integration-test-user" {
		t.Fatalf("SubjectID = %q, want integration-test-user", got.SubjectID)
	}

	if err := store.DeleteSession(context.Background(), "integration-test-session"); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
}
