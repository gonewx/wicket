// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package storage_test

import (
	"encoding/json"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/storage/models"
)

var codecTestInstant = time.Date(2026, 11, 14, 8, 30, 0, 0, time.UTC)

// fillExported sets every exported field reachable from v to a non-zero
// value, so a round trip covers fields added to the client later as well.
func fillExported(t *testing.T, v reflect.Value, seed string) {
	t.Helper()
	switch v.Kind() {
	case reflect.Struct:
		if v.Type() == reflect.TypeOf(time.Time{}) {
			v.Set(reflect.ValueOf(codecTestInstant))
			return
		}
		for i := 0; i < v.NumField(); i++ {
			field := v.Type().Field(i)
			if !field.IsExported() {
				continue
			}
			fillExported(t, v.Field(i), seed+"."+field.Name)
		}
	case reflect.Pointer:
		elem := reflect.New(v.Type().Elem())
		fillExported(t, elem.Elem(), seed)
		v.Set(elem)
	case reflect.Slice:
		slice := reflect.MakeSlice(v.Type(), 2, 2)
		for i := 0; i < 2; i++ {
			fillExported(t, slice.Index(i), seed+"["+string(rune('a'+i))+"]")
		}
		v.Set(slice)
	case reflect.Map:
		m := reflect.MakeMap(v.Type())
		key := reflect.New(v.Type().Key()).Elem()
		fillExported(t, key, seed+".key")
		value := reflect.New(v.Type().Elem()).Elem()
		fillExported(t, value, seed+".value")
		m.SetMapIndex(key, value)
		v.Set(m)
	case reflect.String:
		v.SetString(seed)
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(int64(len(seed)%7 + 2))
	default:
		t.Fatalf("fillExported: unhandled kind %s at %s", v.Kind(), seed)
	}
}

func fullyPopulatedClient(t *testing.T) *models.Client {
	t.Helper()
	client := &models.Client{}
	fillExported(t, reflect.ValueOf(client).Elem(), "client")
	value := reflect.ValueOf(client).Elem()
	for i := 0; i < value.NumField(); i++ {
		field := value.Type().Field(i)
		if field.IsExported() && value.Field(i).IsZero() {
			t.Fatalf("field %s left zero", field.Name)
		}
	}
	if err := client.SetAllowedGrantTypes([]string{wicket.GrantTypeAuthorizationCode, wicket.GrantTypeClientCredentials}); err != nil {
		t.Fatalf("SetAllowedGrantTypes: %v", err)
	}
	return client
}

func TestClientCodecRoundTrip(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		client func(t *testing.T) *models.Client
	}{
		"every field populated": {client: fullyPopulatedClient},
		"defaults without grant types": {client: func(*testing.T) *models.Client {
			client := models.NewClient()
			client.ClientId = "defaults"
			return client
		}},
		"empty grant types": {client: func(t *testing.T) *models.Client {
			client := models.NewClient()
			client.ClientId = "empty"
			if err := client.SetAllowedGrantTypes([]string{}); err != nil {
				t.Fatalf("SetAllowedGrantTypes: %v", err)
			}
			return client
		}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			original := tc.client(t)
			data, err := storage.EncodeClient(original)
			if err != nil {
				t.Fatalf("EncodeClient: %v", err)
			}
			decoded, err := storage.DecodeClient(data)
			if err != nil {
				t.Fatalf("DecodeClient: %v", err)
			}
			if !reflect.DeepEqual(decoded, original) {
				t.Fatalf("round trip mismatch:\n got %#v\nwant %#v", decoded, original)
			}
			if !slices.Equal(decoded.AllowedGrantTypes(), original.AllowedGrantTypes()) ||
				(decoded.AllowedGrantTypes() == nil) != (original.AllowedGrantTypes() == nil) {
				t.Fatalf("AllowedGrantTypes = %#v, want %#v", decoded.AllowedGrantTypes(), original.AllowedGrantTypes())
			}
		})
	}
}

func TestClientCodecRejectsBadInput(t *testing.T) {
	t.Parallel()

	valid, err := storage.EncodeClient(models.NewClient())
	if err != nil {
		t.Fatalf("EncodeClient: %v", err)
	}
	withVersion := func(version int) []byte {
		var envelope map[string]json.RawMessage
		if err := json.Unmarshal(valid, &envelope); err != nil {
			t.Fatalf("unmarshal envelope: %v", err)
		}
		envelope["version"] = json.RawMessage([]byte{byte('0' + version)})
		data, err := json.Marshal(envelope)
		if err != nil {
			t.Fatalf("marshal envelope: %v", err)
		}
		return data
	}

	tests := map[string][]byte{
		"unknown version":         withVersion(2),
		"missing version":         withVersion(0),
		"truncated":               valid[:len(valid)/2],
		"not json":                []byte("not json"),
		"empty":                   {},
		"null client":             []byte(`{"version":1,"client":null}`),
		"missing client":          []byte(`{"version":1}`),
		"client of wrong shape":   []byte(`{"version":1,"client":[1,2]}`),
		"invalid grant types":     []byte(`{"version":1,"client":{},"allowed_grant_types":["implicit","authorization_code"]}`),
		"grant type with a space": []byte(`{"version":1,"client":{},"allowed_grant_types":["a b"]}`),
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			client, err := storage.DecodeClient(data)
			if err == nil {
				t.Fatal("DecodeClient accepted bad input")
			}
			if client != nil {
				t.Fatalf("DecodeClient returned a client (%v) with its error", client)
			}
		})
	}

	t.Run("nil client", func(t *testing.T) {
		t.Parallel()
		if data, err := storage.EncodeClient(nil); err == nil || data != nil {
			t.Fatalf("EncodeClient(nil) = %q, %v; want an error and no bytes", data, err)
		}
	})
}

// TestClientCodecDecodesGoldenV1 pins the version 1 wire format: bytes already
// persisted under version 1 must keep decoding to the same field values, so a
// renamed client field cannot silently drop stored data.
func TestClientCodecDecodesGoldenV1(t *testing.T) {
	t.Parallel()

	golden := []byte(`{
		"version": 1,
		"client": {
			"Enabled": true,
			"ClientId": "golden-client",
			"ClientName": "Golden",
			"ClientSecrets": [{"Description": "primary", "Value": "c2VjcmV0LWhhc2g=", "Expiration": "2027-01-02T03:04:05Z", "Type": "SharedSecret"}],
			"RedirectUris": ["https://golden.example/cb"],
			"AccessTokenLifetime": 1800,
			"AllowedCorsOrigins": ["https://golden.example"],
			"TokenEndpointAuthMethod": "private_key_jwt",
			"JwksUri": "https://golden.example/jwks"
		},
		"allowed_grant_types": ["authorization_code", "client_credentials"]
	}`)

	client, err := storage.DecodeClient(golden)
	if err != nil {
		t.Fatalf("DecodeClient(golden v1): %v", err)
	}
	checks := map[string]struct{ got, want any }{
		"Enabled":                 {client.Enabled, true},
		"ClientId":                {client.ClientId, "golden-client"},
		"ClientName":              {client.ClientName, "Golden"},
		"RedirectUris":            {client.RedirectUris, []string{"https://golden.example/cb"}},
		"AccessTokenLifetime":     {client.AccessTokenLifetime, 1800},
		"AllowedCorsOrigins":      {client.AllowedCorsOrigins, []string{"https://golden.example"}},
		"TokenEndpointAuthMethod": {client.TokenEndpointAuthMethod, "private_key_jwt"},
		"JwksUri":                 {client.JwksUri, "https://golden.example/jwks"},
		"RequirePkce (absent)":    {client.RequirePkce, true},
		"AllowedGrantTypes":       {client.AllowedGrantTypes(), []string{wicket.GrantTypeAuthorizationCode, wicket.GrantTypeClientCredentials}},
		"ClientSecrets": {client.ClientSecrets, []*models.Secret{{
			Description: "primary",
			Value:       "c2VjcmV0LWhhc2g=",
			Expiration:  time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC),
			Type:        wicket.SecretTypesSharedSecret,
		}}},
	}
	for name, check := range checks {
		if !reflect.DeepEqual(check.got, check.want) {
			t.Errorf("%s = %#v, want %#v", name, check.got, check.want)
		}
	}
}
