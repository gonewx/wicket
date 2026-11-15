// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package di

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket"
	responses_models "github.com/gonewx/wicket/responses/models"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/storage"
	storage_models "github.com/gonewx/wicket/storage/models"
)

func TestSetRefreshTokenConsumption(t *testing.T) {
	t.Parallel()

	cfg := NewServerConfig()
	if got := cfg.RefreshTokenConsumption(); got != services.RefreshTokenKeptOnRedemption {
		t.Fatalf("default consumption %v, want kept", got)
	}
	cfg.SetRefreshTokenConsumption(services.RefreshTokenMarkedOnRedemption)
	if got := cfg.RefreshTokenConsumption(); got != services.RefreshTokenMarkedOnRedemption {
		t.Fatalf("declared consumption %v, want marked", got)
	}
	var nilConfig *ServerConfig
	if got := nilConfig.RefreshTokenConsumption(); got != services.RefreshTokenKeptOnRedemption {
		t.Fatalf("nil configuration reports %v", got)
	}
}

func TestSetRefreshTokenConsumptionPanics(t *testing.T) {
	cases := map[string]struct {
		call   func(*ServerConfig)
		freeze bool
		want   string
	}{
		"after Freeze": {
			call:   func(cfg *ServerConfig) { cfg.SetRefreshTokenConsumption(services.RefreshTokenRemovedOnRedemption) },
			freeze: true,
			want:   "after Freeze",
		},
		"undeclared value": {
			call: func(cfg *ServerConfig) { cfg.SetRefreshTokenConsumption(services.RefreshTokenConsumption(-1)) },
			want: "undeclared value",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, cfg := newAssertionRoot(t)
			if tc.freeze {
				cfg.Freeze()
			}
			text := panicText(t, func() { tc.call(cfg) })
			if !strings.Contains(text, "SetRefreshTokenConsumption") || !strings.Contains(text, tc.want) {
				t.Fatalf("panic text %q", text)
			}
		})
	}
}

// The resolved refresh token service rotates a one-time refresh token only
// under a consumption that rotates.
func TestRefreshTokenServiceAssemblyAppliesConsumption(t *testing.T) {
	cases := map[string]struct {
		consumption *services.RefreshTokenConsumption
		rotates     bool
	}{
		"default": {},
		"kept":    {consumption: new(services.RefreshTokenKeptOnRedemption)},
		"removed": {consumption: new(services.RefreshTokenRemovedOnRedemption), rotates: true},
		"marked":  {consumption: new(services.RefreshTokenMarkedOnRedemption), rotates: true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			root, cfg := newAssertionRoot(t)
			if tc.consumption != nil {
				cfg.SetRefreshTokenConsumption(*tc.consumption)
			}
			cfg.Freeze()

			client := storage_models.NewClient()
			client.ClientId = "client"
			client.RefreshTokenUsage = wicket.TokenUsageOneTimeOnly
			token := storage_models.NewRefreshToken()
			token.ClientId = client.ClientId
			store := godi.GetRequired[storage.RefreshTokenStore](root)
			if err := store.StoreRefreshToken(context.Background(), "R", token); err != nil {
				t.Fatalf("store: %v", err)
			}

			service := godi.GetRequired[services.RefreshTokenService](root)
			validated := service.ValidateRefreshToken(context.Background(), "R", client)
			if validated.Error != nil {
				t.Fatalf("validate: %v", validated.Error)
			}
			handle, err := service.UpdateRefreshToken(context.Background(), &responses_models.RefreshTokenUpdateRequest{
				Handle:       "R",
				Client:       client,
				RefreshToken: validated.RefreshToken,
			})
			if err != nil {
				t.Fatalf("update: %v", err)
			}
			if rotated := handle != "R"; rotated != tc.rotates {
				t.Fatalf("handle %q: rotated %v, want %v", handle, rotated, tc.rotates)
			}
			replay := service.ValidateRefreshToken(context.Background(), "R", client)
			if refused := errors.Is(replay.Error, storage.ErrNotFound); refused != tc.rotates {
				t.Fatalf("redeemed handle refused %v (%v), want %v", refused, replay.Error, tc.rotates)
			}
		})
	}
}
