// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gonewx/wicket"
	config_options "github.com/gonewx/wicket/config/options"
	services_impl "github.com/gonewx/wicket/services/impl"
	"github.com/gonewx/wicket/storage/memory"
	storage_models "github.com/gonewx/wicket/storage/models"
	validators_models "github.com/gonewx/wicket/validators/models"
)

type cibaTestClock struct {
	now time.Time
}

func (c *cibaTestClock) Now() time.Time {
	return c.now
}

func TestBackchannelAuthenticationRequestValidatorTable(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name    string
		client  func(*storage_models.Client)
		values  url.Values
		wantErr error
	}{
		{
			name: "success stores opaque poll request",
			values: url.Values{
				gois.BackchannelAuthenticationRequestScope:     {"openid api"},
				gois.BackchannelAuthenticationRequestLoginHint: {"alice"},
			},
		},
		{
			name: "unsupported delivery mode",
			client: func(c *storage_models.Client) {
				c.BackchannelTokenDeliveryMode = gois.BackchannelTokenDeliveryModesPush
			},
			values: url.Values{
				gois.BackchannelAuthenticationRequestScope:     {"openid api"},
				gois.BackchannelAuthenticationRequestLoginHint: {"alice"},
			},
			wantErr: gois.TokenErrorsInvalidRequest,
		},
		{
			name: "missing user hint",
			values: url.Values{
				gois.BackchannelAuthenticationRequestScope: {"openid api"},
			},
			wantErr: gois.TokenErrorsInvalidRequest,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			options := config_options.NewWicketOptions()
			store := memory.NewMemoryBackchannelAuthenticationRequestStore()
			validator := newCIBARequestValidator(t, options, store)
			client := newCIBAClient(t)
			if tt.client != nil {
				tt.client(client)
			}

			result := validator.Validate(context.Background(), tt.values, client)
			if !errors.Is(result.Error, tt.wantErr) {
				t.Fatalf("error = %v, want %v", result.Error, tt.wantErr)
			}
			if tt.wantErr != nil {
				return
			}
			if result.Request == nil || result.Request.RequestId == "" {
				t.Fatal("missing stored request id")
			}
			if len(result.Request.RequestId) < 27 {
				t.Fatalf("auth_req_id length = %d, want at least 27", len(result.Request.RequestId))
			}
			for _, r := range result.Request.RequestId {
				if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", r) {
					t.Fatalf("auth_req_id contains invalid rune %q", r)
				}
			}
			stored, err := store.FindBackchannelAuthenticationRequest(context.Background(), result.Request.RequestId)
			if err != nil {
				t.Fatalf("find stored request: %v", err)
			}
			if stored == nil || stored.ClientId != client.ClientId || stored.Subject == nil {
				t.Fatalf("stored request = %#v", stored)
			}
		})
	}
}

func TestBackchannelAuthenticationRequestIdValidatorTable(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 8, 8, 0, 0, 0, time.UTC)
	for _, tt := range []struct {
		name         string
		request      *storage_models.BackchannelAuthenticationRequest
		wantErr      error
		wantInterval int
	}{
		{
			name: "pending first poll",
			request: &storage_models.BackchannelAuthenticationRequest{
				RequestId:      "req",
				ClientId:       "client",
				Status:         storage_models.BackchannelAuthenticationRequestStatusPending,
				ExpirationTime: now.Add(time.Minute),
				PollInterval:   5,
			},
			wantErr: gois.TokenErrorsAuthorizationPending,
		},
		{
			name: "slow down increases interval",
			request: &storage_models.BackchannelAuthenticationRequest{
				RequestId:      "req",
				ClientId:       "client",
				Status:         storage_models.BackchannelAuthenticationRequestStatusPending,
				ExpirationTime: now.Add(time.Minute),
				PollInterval:   5,
				LastPollTime:   &now,
			},
			wantErr:      gois.TokenErrorsSlowDown,
			wantInterval: 10,
		},
		{
			name: "expired",
			request: &storage_models.BackchannelAuthenticationRequest{
				RequestId:      "req",
				ClientId:       "client",
				Status:         storage_models.BackchannelAuthenticationRequestStatusPending,
				ExpirationTime: now.Add(-time.Second),
			},
			wantErr: gois.TokenErrorsExpiredToken,
		},
		{
			name: "consumed is invalid grant",
			request: &storage_models.BackchannelAuthenticationRequest{
				RequestId:      "req",
				ClientId:       "client",
				Status:         storage_models.BackchannelAuthenticationRequestStatusConsumed,
				ExpirationTime: now.Add(time.Minute),
			},
			wantErr: gois.TokenErrorsInvalidGrant,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			options := config_options.NewWicketOptions()
			clock := &cibaTestClock{now: now}
			store := memory.NewMemoryBackchannelAuthenticationRequestStore()
			if err := store.StoreBackchannelAuthenticationRequest(context.Background(), tt.request.RequestId, tt.request); err != nil {
				t.Fatalf("store request: %v", err)
			}
			validator := NewBackchannelAuthenticationRequestIdValidator(
				store,
				services_impl.NewBackchannelAuthenticationThrottlingService(options, clock),
				clock,
			)
			request := validators_models.NewValidatedTokenRequest()
			request.SetClient(newCIBAClient(t), nil, "")
			validation := &validators_models.BackchannelAuthenticationRequestIdValidationContext{
				RequestId: tt.request.RequestId,
				Request:   request,
			}
			if err := validator.Validate(context.Background(), validation); err != nil {
				t.Fatalf("validate request id: %v", err)
			}
			if !errors.Is(validation.Result.Error, tt.wantErr) {
				t.Fatalf("error = %v, want %v", validation.Result.Error, tt.wantErr)
			}
			if tt.wantInterval > 0 && tt.request.PollInterval != tt.wantInterval {
				t.Fatalf("poll interval = %d, want %d", tt.request.PollInterval, tt.wantInterval)
			}
		})
	}
}

func newCIBARequestValidator(t *testing.T, options *config_options.WicketOptions, store *memory.MemoryBackchannelAuthenticationRequestStore) *BackchannelAuthenticationRequestValidator {
	t.Helper()

	identity := storage_models.NewIdentityResource()
	identity.Name = gois.StandardScopesOpenId
	apiScope := storage_models.NewApiScope()
	apiScope.Name = "api"
	apiResource := storage_models.NewApiResource()
	apiResource.Name = "api-resource"
	apiResource.Scopes = []string{"api"}
	resourceStore, err := memory.NewMemoryResourcesStore([]*storage_models.IdentityResource{identity}, []*storage_models.ApiResource{apiResource}, []*storage_models.ApiScope{apiScope})
	if err != nil {
		t.Fatalf("resource store: %v", err)
	}
	return NewBackchannelAuthenticationRequestValidator(
		options,
		store,
		NewResourceValidator(resourceStore, NewScopeParser(), slog.Default()),
		NewBackchannelAuthenticationUserValidator(),
		services_impl.NewBackchannelAuthenticationNotificationService(nil),
		&cibaTestClock{now: time.Date(2026, 7, 8, 8, 0, 0, 0, time.UTC)},
		slog.Default(),
	)
}

func newCIBAClient(t *testing.T) *storage_models.Client {
	t.Helper()

	client := storage_models.NewClient()
	client.ClientId = "client"
	client.RequireClientSecret = false
	if err := client.SetAllowedGrantTypes(gois.GrantTypesBackchannelAuthentication); err != nil {
		t.Fatalf("set grant types: %v", err)
	}
	client.AllowedScopes = []string{gois.StandardScopesOpenId, "api"}
	return client
}
