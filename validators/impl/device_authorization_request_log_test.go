// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"strings"
	"testing"

	"github.com/gonewx/wicket"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/models"
	"github.com/gonewx/wicket/storage/memory"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/utils"
	validators_mock "github.com/gonewx/wicket/validators/mock"
	validators_models "github.com/gonewx/wicket/validators/models"
)

const (
	deviceLogClientId = "device.log.client"
	// deviceLogPostedSecret is the client secret as a client authenticating in
	// the request body sends it; the validator is handed the whole form.
	deviceLogPostedSecret = "posted-device-client-secret"
	// deviceLogParsedSecret is the credential the secret parser extracted.
	deviceLogParsedSecret = "parsed-device-client-secret"
	deviceLogClientName   = "Device Log Client"
	deviceLogRedirectUri  = "https://device.example/cb"
)

// deviceLogFormats are the two handlers of log/slog. They write a value handed
// over as a whole differently, so each is checked on its own.
var deviceLogFormats = []struct {
	name       string
	newHandler func(io.Writer, *slog.HandlerOptions) slog.Handler
	record     func(message string, protocolType string) string
}{
	{
		name: "json",
		newHandler: func(w io.Writer, opts *slog.HandlerOptions) slog.Handler {
			return slog.NewJSONHandler(w, opts)
		},
		record: func(message string, protocolType string) string {
			if protocolType != "" {
				return fmt.Sprintf(`{"level":"ERROR","msg":%q,"protocolType":%q,"clientId":%q}`, message, protocolType, deviceLogClientId)
			}
			return fmt.Sprintf(`{"level":"ERROR","msg":%q,"clientId":%q}`, message, deviceLogClientId)
		},
	},
	{
		name: "text",
		newHandler: func(w io.Writer, opts *slog.HandlerOptions) slog.Handler {
			return slog.NewTextHandler(w, opts)
		},
		record: func(message string, protocolType string) string {
			if protocolType != "" {
				return fmt.Sprintf("level=ERROR msg=%q protocolType=%s clientId=%s", message, protocolType, deviceLogClientId)
			}
			return fmt.Sprintf("level=ERROR msg=%q clientId=%s", message, deviceLogClientId)
		},
	},
}

// deviceLogClient returns a device flow client holding a hashed secret,
// together with that hashed value.
func deviceLogClient() (*storage_models.Client, string) {
	hashedSecret := utils.Sha256("device-client-secret")

	secret := storage_models.NewSecret()
	secret.Value = hashedSecret

	client := storage_models.NewClient()
	client.ClientId = deviceLogClientId
	client.ClientName = deviceLogClientName
	client.ClientSecrets = []*storage_models.Secret{secret}
	client.RedirectUris = []string{deviceLogRedirectUri}
	if err := client.SetAllowedGrantTypes(wicket.GrantTypesDeviceFlow); err != nil {
		panic(err)
	}
	client.AllowedScopes = []string{"openid", "profile", "resource"}
	return client, hashedSecret
}

func dropDeviceLogTime(groups []string, attr slog.Attr) slog.Attr {
	if len(groups) == 0 && attr.Key == slog.TimeKey {
		return slog.Attr{}
	}
	return attr
}

// Every refusal of a device authorization request that is logged at error
// level names the client and carries neither the posted secret, the parsed
// credential nor anything of the client beyond its id.
func TestDeviceAuthorizationRequestValidatorErrorLogCarriesNoCredentials(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name         string
		scope        string
		prepare      func(client *storage_models.Client, options *config_options.WicketOptions)
		wantMessage  string
		wantProtocol string
		wantErr      error
	}{
		{
			name:  "invalid protocol type",
			scope: "resource",
			prepare: func(client *storage_models.Client, _ *config_options.WicketOptions) {
				client.ProtocolType = wicket.ProtocolTypesSaml2p
			},
			wantMessage:  "Invalid protocol type for OIDC authorize endpoint",
			wantProtocol: wicket.ProtocolTypesSaml2p,
			wantErr:      wicket.AuthorizeErrorsUnauthorizedClient,
		},
		{
			name:  "client without the device code grant",
			scope: "resource",
			prepare: func(client *storage_models.Client, _ *config_options.WicketOptions) {
				if err := client.SetAllowedGrantTypes(wicket.GrantTypesCode); err != nil {
					panic(err)
				}
			},
			wantMessage: "Client does not allow device flow",
			wantErr:     wicket.AuthorizeErrorsUnauthorizedClient,
		},
		{
			name:        "no scope and no allowed scopes",
			prepare:     func(client *storage_models.Client, _ *config_options.WicketOptions) { client.AllowedScopes = nil },
			wantMessage: "No allowed scopes configured for client",
			wantErr:     wicket.AuthorizeErrorsInvalidScope,
		},
		{
			name:  "scope too long",
			scope: strings.Repeat("s", 40),
			prepare: func(_ *storage_models.Client, options *config_options.WicketOptions) {
				options.InputLengthRestrictions.Scope = 10
			},
			wantMessage: "Scope too long",
			wantErr:     wicket.AuthorizeErrorsInvalidRequest,
		},
		{
			name:        "identity scope without openid",
			scope:       "profile",
			wantMessage: "Identity related scope requests, but no openid scope",
			wantErr:     wicket.AuthorizeErrorsInvalidScope,
		},
	}

	for _, format := range deviceLogFormats {
		for _, tc := range cases {
			t.Run(format.name+"/"+tc.name, func(t *testing.T) {
				t.Parallel()

				var logs bytes.Buffer
				logger := slog.New(format.newHandler(&logs, &slog.HandlerOptions{
					Level:       slog.LevelDebug,
					ReplaceAttr: dropDeviceLogTime,
				}))

				options := config_options.NewWicketOptions()
				client, hashedSecret := deviceLogClient()
				if tc.prepare != nil {
					tc.prepare(client, options)
				}

				scopes := &validators_mock.TestScopes{}
				resourceStore, err := memory.NewMemoryResourcesStore(scopes.GetIdentity(), scopes.GetApis(), scopes.GetScopes())
				if err != nil {
					t.Fatalf("resource store: %v", err)
				}
				validator := NewDeviceAuthorizationRequestValidator(
					options,
					NewResourceValidator(resourceStore, NewScopeParser(), logger),
					logger,
				)

				parameters := url.Values{}
				parameters.Set("client_id", deviceLogClientId)
				parameters.Set("client_secret", deviceLogPostedSecret)
				if tc.scope != "" {
					parameters.Set("scope", tc.scope)
				}

				clientResult := validators_models.NewClientSecretValidationResult()
				clientResult.Client = client
				clientResult.Secret = &models.ParsedSecret{
					Id:         deviceLogClientId,
					Credential: deviceLogParsedSecret,
					Type:       wicket.ParsedSecretTypesSharedSecret,
				}

				result := validator.ValidateRequest(context.Background(), parameters, clientResult)
				if result.Error != tc.wantErr {
					t.Fatalf("result error = %v, want %v", result.Error, tc.wantErr)
				}

				var records []string
				for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
					if strings.Contains(line, tc.wantMessage) {
						records = append(records, line)
					}
				}
				if len(records) != 1 {
					t.Fatalf("records of %q = %d, want 1: %s", tc.wantMessage, len(records), logs.String())
				}
				if want := format.record(tc.wantMessage, tc.wantProtocol); records[0] != want {
					t.Errorf("record = %s, want %s", records[0], want)
				}

				for _, fragment := range []string{
					deviceLogPostedSecret,
					deviceLogParsedSecret,
					hashedSecret,
					deviceLogClientName,
					deviceLogRedirectUri,
					// Field names of the request, the parsed secret and the client.
					"Raw", "Credential", "ClientSecrets", "ClientName", "RedirectUris", "ValidatedRequest",
				} {
					if strings.Contains(logs.String(), fragment) {
						t.Errorf("log carries %q: %s", fragment, logs.String())
					}
				}
			})
		}
	}
}
