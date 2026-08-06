// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package e2e_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gonewx/wicket"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/handlers"
	services_impl "github.com/gonewx/wicket/services/impl"
	"github.com/gonewx/wicket/storage/memory"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/validators"
	validators_impl "github.com/gonewx/wicket/validators/impl"
)

type cibaE2EClock struct {
	now time.Time
}

func (c cibaE2EClock) Now() time.Time {
	return c.now
}

type cibaE2EFixture struct {
	handler  *handlers.BackchannelAuthenticationHandler
	requests *memory.MemoryBackchannelAuthenticationRequestStore
	client   *storage_models.Client
	now      time.Time
}

func TestCIBABackchannelAuthenticationPollRequestE2E(t *testing.T) {
	t.Parallel()

	fixture := newCIBAE2EFixture(t)
	form := url.Values{
		gois.AuthorizeRequestClientId:                        {fixture.client.ClientId},
		gois.BackchannelAuthenticationRequestScope:           {gois.StandardScopesOpenId + " api"},
		gois.BackchannelAuthenticationRequestResource:        {"https://resources.example.com/api"},
		gois.BackchannelAuthenticationRequestLoginHint:       {"alice"},
		gois.BackchannelAuthenticationRequestBindingMessage:  {"Transfer 100 USD"},
		gois.BackchannelAuthenticationRequestUserCode:        {"123456"},
		gois.BackchannelAuthenticationRequestRequestedExpiry: {"120"},
	}

	rec, body := postCIBAE2E(t, fixture.handler, form)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if cacheControl := strings.Join(rec.Header().Values("Cache-Control"), ","); !strings.Contains(cacheControl, "no-store") || !strings.Contains(cacheControl, "no-cache") {
		t.Fatalf("Cache-Control = %q, want no-store and no-cache", cacheControl)
	}
	authReqID, ok := body["auth_req_id"].(string)
	if !ok || len(authReqID) < 27 {
		t.Fatalf("auth_req_id = %#v, want opaque request id", body["auth_req_id"])
	}
	if body["expires_in"] != float64(120) {
		t.Fatalf("expires_in = %#v, want 120", body["expires_in"])
	}
	if body["interval"] != float64(7) {
		t.Fatalf("interval = %#v, want 7", body["interval"])
	}

	stored, err := fixture.requests.FindBackchannelAuthenticationRequest(context.Background(), authReqID)
	if err != nil {
		t.Fatalf("find stored auth request: %v", err)
	}
	if stored == nil {
		t.Fatal("stored auth request is nil")
	}
	if stored.ClientId != fixture.client.ClientId {
		t.Fatalf("stored client id = %q, want %q", stored.ClientId, fixture.client.ClientId)
	}
	if stored.SubjectId != "alice" || stored.Subject == nil {
		t.Fatalf("stored subject = (%q, %#v), want alice subject", stored.SubjectId, stored.Subject)
	}
	if !reflect.DeepEqual(stored.RequestedScopes, []string{gois.StandardScopesOpenId, "api"}) {
		t.Fatalf("stored scopes = %#v", stored.RequestedScopes)
	}
	if !reflect.DeepEqual(stored.RequestedResourceGaps, []string{"https://resources.example.com/api"}) {
		t.Fatalf("stored resource gaps = %#v", stored.RequestedResourceGaps)
	}
	if stored.BindingMessage != "Transfer 100 USD" || stored.UserCode != "123456" {
		t.Fatalf("stored binding/user code = (%q, %q)", stored.BindingMessage, stored.UserCode)
	}
	if stored.Status != storage_models.BackchannelAuthenticationRequestStatusPending {
		t.Fatalf("stored status = %q, want pending", stored.Status)
	}
	if stored.PollInterval != 7 {
		t.Fatalf("stored poll interval = %d, want 7", stored.PollInterval)
	}
	if !stored.ExpirationTime.Equal(fixture.now.Add(120 * time.Second)) {
		t.Fatalf("stored expiration = %s, want %s", stored.ExpirationTime, fixture.now.Add(120*time.Second))
	}
}

func TestCIBABackchannelAuthenticationErrorsE2E(t *testing.T) {
	t.Parallel()

	for name, tt := range map[string]struct {
		form      url.Values
		wantError error
	}{
		"missing client id": {
			form: url.Values{
				gois.BackchannelAuthenticationRequestScope:     {gois.StandardScopesOpenId},
				gois.BackchannelAuthenticationRequestLoginHint: {"alice"},
			},
			wantError: gois.TokenErrorsInvalidRequest,
		},
		"missing user hint": {
			form: url.Values{
				gois.AuthorizeRequestClientId:                  {"ciba-client"},
				gois.BackchannelAuthenticationRequestScope:     {gois.StandardScopesOpenId},
				gois.BackchannelAuthenticationRequestLoginHint: {""},
			},
			wantError: gois.TokenErrorsInvalidRequest,
		},
		"missing scope": {
			form: url.Values{
				gois.AuthorizeRequestClientId:                  {"ciba-client"},
				gois.BackchannelAuthenticationRequestLoginHint: {"alice"},
			},
			wantError: gois.TokenErrorsInvalidScope,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fixture := newCIBAE2EFixture(t)
			rec, body := postCIBAE2E(t, fixture.handler, tt.form)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusBadRequest, rec.Body.String())
			}
			if body["error"] != tt.wantError.Error() {
				t.Fatalf("error = %#v, want %q", body["error"], tt.wantError.Error())
			}
		})
	}
}

func newCIBAE2EFixture(t *testing.T) *cibaE2EFixture {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	options := config_options.NewWicketOptions()
	now := time.Date(2026, 7, 8, 8, 0, 0, 0, time.UTC)
	clock := cibaE2EClock{now: now}
	requestStore := memory.NewMemoryBackchannelAuthenticationRequestStore()
	client := newCIBAE2EClient(t)
	clientStore, err := memory.NewMemoryClientStore([]*storage_models.Client{client})
	if err != nil {
		t.Fatalf("client store: %v", err)
	}

	resourceStore, err := memory.NewMemoryResourcesStore(
		[]*storage_models.IdentityResource{newCIBAE2EIdentityResource()},
		[]*storage_models.ApiResource{newCIBAE2EAPIResource()},
		[]*storage_models.ApiScope{newCIBAE2EAPIScope()},
	)
	if err != nil {
		t.Fatalf("resource store: %v", err)
	}

	secretParser := validators_impl.NewSecretParser([]validators.SecretParser{
		validators_impl.NewPostBodySecretParser(logger, options),
	}, logger)
	clientValidator := validators_impl.NewClientSecretValidator(
		logger,
		clientStore,
		validators_impl.NewSecretValidator(clock, nil, logger),
		secretParser,
	)
	requestValidator := validators_impl.NewBackchannelAuthenticationRequestValidator(
		options,
		requestStore,
		validators_impl.NewResourceValidator(resourceStore, validators_impl.NewScopeParser(), logger),
		validators_impl.NewBackchannelAuthenticationUserValidator(),
		services_impl.NewBackchannelAuthenticationNotificationService(nil),
		clock,
		logger,
	)

	return &cibaE2EFixture{
		handler:  handlers.NewBackchannelAuthenticationHandler(clientValidator, requestValidator),
		requests: requestStore,
		client:   client,
		now:      now,
	}
}

func newCIBAE2EClient(t *testing.T) *storage_models.Client {
	t.Helper()

	pollInterval := 7
	client := storage_models.NewClient()
	client.ClientId = "ciba-client"
	client.RequireClientSecret = false
	client.AllowedScopes = []string{gois.StandardScopesOpenId, "api"}
	client.PollingInterval = &pollInterval
	if err := client.SetAllowedGrantTypes(gois.GrantTypesBackchannelAuthentication); err != nil {
		t.Fatalf("set grant types: %v", err)
	}
	return client
}

func newCIBAE2EIdentityResource() *storage_models.IdentityResource {
	resource := storage_models.NewIdentityResource()
	resource.Name = gois.StandardScopesOpenId
	return resource
}

func newCIBAE2EAPIResource() *storage_models.ApiResource {
	resource := storage_models.NewApiResource()
	resource.Name = "https://resources.example.com/api"
	resource.Scopes = []string{"api"}
	return resource
}

func newCIBAE2EAPIScope() *storage_models.ApiScope {
	scope := storage_models.NewApiScope()
	scope.Name = "api"
	return scope
}

func postCIBAE2E(t *testing.T, handler *handlers.BackchannelAuthenticationHandler, form url.Values) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/connect/ciba", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	if err := handler.Process(rec, req); err != nil {
		t.Fatalf("process CIBA request: %v", err)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response body %q: %v", rec.Body.String(), err)
	}
	return rec, body
}
