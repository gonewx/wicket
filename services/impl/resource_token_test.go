// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"reflect"
	"testing"
	"time"

	responses_models "github.com/gonewx/wicket/responses/models"
	"github.com/gonewx/wicket/storage/models"
	validators_models "github.com/gonewx/wicket/validators/models"
)

type resourceTokenClock struct{}

func (resourceTokenClock) Now() time.Time {
	return time.Date(2026, 7, 8, 9, 0, 0, 0, time.UTC)
}

func TestTokenServiceUsesSelectedApiResourcesAsAudience(t *testing.T) {
	t.Parallel()

	apiResource := models.NewApiResource()
	apiResource.Name = "https://resources.example.com/orders"
	apiScope := models.NewApiScope()
	apiScope.Name = "orders.read"
	token, err := (&TokenService{clock: resourceTokenClock{}}).CreateAccessToken(&responses_models.TokenCreationRequest{
		ValidatedResources: validators_models.NewResourceValidationResultWithResources(models.NewResources(
			models.WithResourcesApiResources([]*models.ApiResource{apiResource}),
			models.WithResourcesApiScopes([]*models.ApiScope{apiScope}),
		)),
	})
	if err != nil {
		t.Fatalf("CreateAccessToken error: %v", err)
	}
	if !reflect.DeepEqual(token.Audiences, []string{apiResource.Name}) {
		t.Fatalf("Audiences = %v, want %v", token.Audiences, []string{apiResource.Name})
	}
}

func TestRefreshTokenServiceUpdatesRequestedResourceAccessToken(t *testing.T) {
	t.Parallel()

	store := &resourceRefreshTokenStore{}
	service := NewRefreshTokenService(store)
	refreshToken := models.NewRefreshToken()
	refreshToken.SetAccessToken(&models.Token{ClientId: "default"}, "")
	refreshToken.SetAccessToken(&models.Token{ClientId: "payments"}, "https://resources.example.com/payments")
	ordersToken := &models.Token{ClientId: "orders"}

	handle, err := service.UpdateRefreshToken(&responses_models.RefreshTokenUpdateRequest{
		Handle:               "handle",
		RefreshToken:         refreshToken,
		AccessToken:          ordersToken,
		RequestedResourceGap: "https://resources.example.com/orders",
	})
	if err != nil {
		t.Fatalf("UpdateRefreshToken error: %v", err)
	}
	if handle != "handle" {
		t.Fatalf("handle = %q, want handle", handle)
	}
	if got := refreshToken.GetAccessToken("https://resources.example.com/orders"); got != ordersToken {
		t.Fatalf("orders access token = %#v, want %#v", got, ordersToken)
	}
	if got := refreshToken.GetAccessToken(""); got == ordersToken {
		t.Fatal("default access token was overwritten by resource-specific token")
	}
	if got := refreshToken.GetAccessToken("https://resources.example.com/payments"); got == nil || got.ClientId != "payments" {
		t.Fatalf("payments access token = %#v, want existing payments token", got)
	}
	if store.updated != refreshToken {
		t.Fatalf("updated token = %#v, want %#v", store.updated, refreshToken)
	}
}

type resourceRefreshTokenStore struct {
	updated *models.RefreshToken
}

func (s *resourceRefreshTokenStore) StoreRefreshToken(token *models.RefreshToken) (string, error) {
	return "handle", nil
}

func (s *resourceRefreshTokenStore) GetRefreshToken(string) (*models.RefreshToken, error) {
	return nil, nil
}

func (s *resourceRefreshTokenStore) UpdateRefreshToken(_ string, token *models.RefreshToken) error {
	s.updated = token
	return nil
}

func (s *resourceRefreshTokenStore) RemoveRefreshToken(string) error {
	return nil
}
