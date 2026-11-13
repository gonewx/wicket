// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/gonewx/wicket"
	validators_mock "github.com/gonewx/wicket/validators/mock"
)

// TestTokenRequestValidationDeviceFlowInvalid verifies the failure paths of
// the device code grant: parameter presence and length, grant type
// permission, device code verification, and the resource parameter ban.
func TestTokenRequestValidationDeviceFlowInvalid(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		clientId   string
		options    []tokenGrantOption
		deviceCode string
		resource   string
		wantErr    error
		wantAnyErr bool
	}{
		"missing device_code parameter is rejected": {
			clientId: "device_flow",
			wantErr:  wicket.TokenErrorsInvalidRequest,
		},
		"device_code exceeding the maximum length is rejected": {
			clientId:   "device_flow",
			deviceCode: "over-limit",
			wantErr:    wicket.TokenErrorsInvalidGrant,
		},
		"client without device flow permission is rejected": {
			clientId:   "codeclient",
			deviceCode: "device",
			wantErr:    wicket.TokenErrorsUnauthorizedClient,
		},
		"device code verification failure is surfaced": {
			clientId:   "device_flow",
			options:    []tokenGrantOption{withGrantDeviceCodeValidator(validators_mock.NewTestDeviceCodeValidator(true))},
			deviceCode: "device",
			wantAnyErr: true,
		},
		"resource parameter that is not an absolute URI is rejected": {
			clientId:   "device_flow",
			deviceCode: "device",
			resource:   "api",
			wantErr:    wicket.TokenErrorsInvalidTarget,
		},
		"well-formed resource parameter is still rejected": {
			clientId:   "device_flow",
			deviceCode: "device",
			resource:   "urn:api1",
			wantErr:    wicket.TokenErrorsInvalidTarget,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			f := newTokenGrantFixture(t, tt.options...)
			parameters := url.Values{
				wicket.TokenRequestGrantType: {wicket.GrantTypeDeviceCode},
			}
			if tt.deviceCode != "" {
				deviceCode := tt.deviceCode
				if deviceCode == "over-limit" {
					deviceCode = strings.Repeat("x", f.options.InputLengthRestrictions.DeviceCode+1)
				}
				parameters.Set(wicket.TokenRequestDeviceCode, deviceCode)
			}
			if tt.resource != "" {
				parameters.Set(wicket.TokenRequestResource, tt.resource)
			}

			result, _ := f.validator.ValidateRequest(context.Background(), parameters, grantTestSecretResult(t, tt.clientId))
			if tt.wantAnyErr {
				if result.Error == nil {
					t.Fatal("expected an error from device code verification")
				}
				return
			}
			if !errors.Is(result.Error, tt.wantErr) {
				t.Fatalf("error = %v, want %v", result.Error, tt.wantErr)
			}
		})
	}
}

// TestTokenRequestValidationDeviceFlowValid verifies that an authorized
// device code is exchanged successfully.
func TestTokenRequestValidationDeviceFlowValid(t *testing.T) {
	t.Parallel()

	deviceCodes := validators_mock.NewTestDeviceCodeValidator(false)
	deviceCodes.DeviceCodeResult.ClientId = "device_flow"
	deviceCodes.DeviceCodeResult.IsAuthorized = true
	deviceCodes.DeviceCodeResult.Subject = grantTestSubject("818727")
	deviceCodes.DeviceCodeResult.AuthorizedScopes = []string{"openid", "profile", "resource"}
	deviceCodes.DeviceCodeResult.CreationTime = grantValidationTestNow
	deviceCodes.DeviceCodeResult.Lifetime = 300

	f := newTokenGrantFixture(t, withGrantDeviceCodeValidator(deviceCodes))
	parameters := url.Values{
		wicket.TokenRequestGrantType:  {wicket.GrantTypeDeviceCode},
		wicket.TokenRequestDeviceCode: {"device"},
	}

	result, _ := f.validator.ValidateRequest(context.Background(), parameters, grantTestSecretResult(t, "device_flow"))
	if result.Error != nil {
		t.Fatalf("unexpected error: %v (description %q)", result.Error, result.Description)
	}
}
