// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package e2e_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/gonewx/wicket/di"
	"github.com/gonewx/wicket/storage"
	storage_impl "github.com/gonewx/wicket/storage/impl"
	storage_memory "github.com/gonewx/wicket/storage/memory"
	storage_models "github.com/gonewx/wicket/storage/models"
	validators_contexts "github.com/gonewx/wicket/validators/contexts"
)

// TestObservabilityFallbackWarningUsesInjectedLoggerE2E pins the logging
// contract at the seam level: the warning a lazy wrapper emits when it falls
// back to the in-memory store must reach the logger the host injected, never
// a self-built one. A wrapper that logged on its own would leave the captured
// buffer empty and fail this test. It runs serially: the suite-level
// no-background-activity cases measure goroutine counts and parallel siblings
// perturb their baseline windows.
func TestObservabilityFallbackWarningUsesInjectedLoggerE2E(t *testing.T) {

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	cfg := di.NewServerConfig()
	cfg.AllowInMemoryFallback()

	store := di.NewlazyPersistedGrantStore(cfg, logger)
	if _, err := store.Get(context.Background(), "missing"); err != storage.ErrNotFound {
		t.Fatalf("materialize fallback store: err = %v, want storage.ErrNotFound", err)
	}
	got := buf.String()
	if !strings.Contains(got, "falling back to in-memory") {
		t.Fatalf("fallback warning did not reach the injected logger, captured: %q", got)
	}
	if !strings.Contains(got, "persisted grant store") {
		t.Fatalf("fallback warning does not name the store seam, captured: %q", got)
	}
}

// rejectingClientValidator always fails client configuration validation, so
// the validating store decorator emits its error log line.
type rejectingClientValidator struct{}

func (rejectingClientValidator) Validate(ctx *validators_contexts.ClientConfigurationValidationContext) {
	ctx.SetError("client configuration rejected")
}

// TestObservabilityCredentialMaterialExcludedFromLogsE2E pins the credential
// hygiene contract: log lines emitted while secret-bearing values flow
// through the store adapters must carry identifiers and error text only. The
// client secret and the persisted-grant payload values are chosen to be
// distinctive; if any log line ever embedded one, this test goes red. It
// runs serially for the same goroutine-baseline reason as its sibling.
func TestObservabilityCredentialMaterialExcludedFromLogsE2E(t *testing.T) {

	const clientSecretValue = "shared-secret-x7k9q2-wicket-e2e"
	const grantPayloadValue = "grant-payload-8f3d1a-wicket-e2e"

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	secret := storage_models.NewSecret()
	secret.Value = clientSecretValue
	client := &storage_models.Client{
		ClientId:      "observability-e2e-client",
		ClientSecrets: []*storage_models.Secret{secret},
	}
	inner, err := storage_memory.NewMemoryClientStore([]*storage_models.Client{client})
	if err != nil {
		t.Fatalf("construct client store: %v", err)
	}
	validating := storage_impl.NewValidatingClientStore(
		inner,
		rejectingClientValidator{},
		logger,
	)
	if _, err := validating.FindClientById(context.Background(), client.ClientId); err == nil {
		t.Fatal("rejected client configuration did not surface an error")
	}

	// Exercise a second log-emitting surface: the lazy seam fallback warning,
	// while a credential-like payload sits in the store records.
	cfg := di.NewServerConfig()
	cfg.AllowInMemoryFallback()
	grantStore := di.NewlazyPersistedGrantStore(cfg, logger)
	grant := &storage_models.PersistedGrant{Key: "grant-key-1", Data: []byte(grantPayloadValue)}
	if err := grantStore.Store(context.Background(), grant); err != nil {
		t.Fatalf("store grant with credential-like payload: %v", err)
	}

	logged := buf.String()
	if !strings.Contains(logged, client.ClientId) {
		t.Fatalf("log output does not carry the client identifier, captured: %q", logged)
	}
	if strings.Contains(logged, clientSecretValue) {
		t.Fatalf("client secret value leaked into log output: %q", logged)
	}
	if strings.Contains(logged, grantPayloadValue) {
		t.Fatalf("grant payload value leaked into log output: %q", logged)
	}
}
