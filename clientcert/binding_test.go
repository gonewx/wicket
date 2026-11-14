// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package clientcert

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/certbind"
	storage_models "github.com/gonewx/wicket/storage/models"
	validators_models "github.com/gonewx/wicket/validators/models"
)

const (
	boundClientId    = "bound-client"
	disabledClientId = "disabled-client"
)

type failingClients struct{}

var errStore = errors.New("store down")

func (failingClients) FindClientById(context.Context, string) (*storage_models.Client, error) {
	return nil, errStore
}

type nilClients struct{}

func (nilClients) FindClientById(context.Context, string) (*storage_models.Client, error) {
	return nil, nil
}

func bindingClients() mapClients {
	bound := storage_models.NewClient()
	bound.ClientId = boundClientId
	bound.TlsClientCertificateBoundAccessTokens = true

	plain := storage_models.NewClient()
	plain.ClientId = secretClientId

	disabled := storage_models.NewClient()
	disabled.ClientId = disabledClientId
	disabled.Enabled = false
	disabled.TlsClientCertificateBoundAccessTokens = true

	return mapClients{boundClientId: bound, secretClientId: plain, disabledClientId: disabled}
}

func TestAccessTokenBinderConfirmation(t *testing.T) {
	cert := issue(t, &x509.Certificate{Subject: pkix.Name{CommonName: "bound"}}, nil).cert
	clients := bindingClients()
	ctx := context.Background()
	request := formRequest(url.Values{})

	t.Run("registered client is bound to the presented leaf", func(t *testing.T) {
		other := issue(t, &x509.Certificate{Subject: pkix.Name{CommonName: "other"}}, nil).cert
		got, err := NewAccessTokenBinder(clients, staticSource{cert, other}).Confirmation(ctx, request, boundClientId)
		if err != nil || got != certbind.Confirmation(cert) {
			t.Fatalf("Confirmation = %q, %v; want %q", got, err, certbind.Confirmation(cert))
		}
	})
	t.Run("the default source reads the connection", func(t *testing.T) {
		got, err := NewAccessTokenBinder(clients, nil).Confirmation(ctx, tlsRequest(url.Values{}, cert), boundClientId)
		if err != nil || got != certbind.Confirmation(cert) {
			t.Fatalf("Confirmation = %q, %v", got, err)
		}
	})
	t.Run("unregistered client is not bound", func(t *testing.T) {
		got, err := NewAccessTokenBinder(clients, staticSource{cert}).Confirmation(ctx, request, secretClientId)
		if err != nil || got != "" {
			t.Fatalf("Confirmation = %q, %v; want unbound", got, err)
		}
	})
	t.Run("registered client without a certificate", func(t *testing.T) {
		for name, source := range map[string]CertificateSource{
			"none":     staticSource(nil),
			"nil leaf": staticSource{nil, cert},
		} {
			got, err := NewAccessTokenBinder(clients, source).Confirmation(ctx, request, boundClientId)
			if !errors.Is(err, wicket.TokenErrorsInvalidClient) || got != "" {
				t.Fatalf("%s: Confirmation = %q, %v; want invalid_client", name, got, err)
			}
		}
	})
	t.Run("nil request uses the default source", func(t *testing.T) {
		got, err := NewAccessTokenBinder(clients, nil).Confirmation(ctx, nil, boundClientId)
		if !errors.Is(err, wicket.TokenErrorsInvalidClient) || got != "" {
			t.Fatalf("Confirmation = %q, %v; want invalid_client", got, err)
		}
		got, err = NewAccessTokenBinder(clients, nil).Confirmation(ctx, nil, secretClientId)
		if err != nil || got != "" {
			t.Fatalf("Confirmation = %q, %v; want unbound", got, err)
		}
	})
	t.Run("fails closed when the client is unavailable", func(t *testing.T) {
		cases := map[string]struct {
			binder   *AccessTokenBinder
			clientId string
		}{
			"unknown":     {NewAccessTokenBinder(clients, staticSource{cert}), "unknown"},
			"disabled":    {NewAccessTokenBinder(clients, staticSource{cert}), disabledClientId},
			"store error": {NewAccessTokenBinder(failingClients{}, staticSource{cert}), boundClientId},
			"nil client":  {NewAccessTokenBinder(nilClients{}, staticSource{cert}), boundClientId},
			"empty id":    {NewAccessTokenBinder(clients, staticSource{cert}), ""},
		}
		for name, tc := range cases {
			got, err := tc.binder.Confirmation(ctx, request, tc.clientId)
			if err == nil || got != "" {
				t.Fatalf("%s: Confirmation = %q, %v; want an error", name, got, err)
			}
		}
	})
}

func TestCertificateBindingValidator(t *testing.T) {
	cert := issue(t, &x509.Certificate{Subject: pkix.Name{CommonName: "bound"}}, nil).cert
	clients := bindingClients()
	inner := &innerValidator{clients: clients}
	secret := func(clientId string) url.Values {
		return url.Values{"client_id": {clientId}, "client_secret": {"secret"}}
	}

	t.Run("registered client with a certificate passes", func(t *testing.T) {
		v := NewCertificateBindingValidator(inner, staticSource{cert}, nil)
		result := v.Validate(formRequest(secret(boundClientId)))
		if result.Error != nil || result.Client == nil || result.Client.ClientId != boundClientId {
			t.Fatalf("result = %+v, want success", result)
		}
	})
	t.Run("the default source reads the connection", func(t *testing.T) {
		v := NewCertificateBindingValidator(inner, nil, nil)
		result := v.Validate(tlsRequest(secret(boundClientId), cert))
		if result.Error != nil || result.Client == nil {
			t.Fatalf("result = %+v, want success", result)
		}
		mustFail(t, "default source without tls", v.Validate(formRequest(secret(boundClientId))))
	})
	t.Run("registered client without a certificate fails", func(t *testing.T) {
		mustFail(t, "none", NewCertificateBindingValidator(inner, staticSource(nil), nil).Validate(formRequest(secret(boundClientId))))
		mustFail(t, "nil leaf", NewCertificateBindingValidator(inner, staticSource{nil, cert}, nil).Validate(formRequest(secret(boundClientId))))
	})
	t.Run("unregistered client passes without a certificate", func(t *testing.T) {
		result := NewCertificateBindingValidator(inner, staticSource(nil), nil).Validate(formRequest(secret(secretClientId)))
		if result.Error != nil || result.Client == nil || result.Client.ClientId != secretClientId {
			t.Fatalf("result = %+v, want success", result)
		}
	})
	t.Run("an inner failure is returned unchanged", func(t *testing.T) {
		result := NewCertificateBindingValidator(inner, staticSource{cert}, nil).Validate(formRequest(url.Values{"client_id": {boundClientId}, "client_secret": {"wrong"}}))
		if !errors.Is(result.Error, errInner) {
			t.Fatalf("result = %+v, want the inner failure", result)
		}
	})
	t.Run("nil request", func(t *testing.T) {
		if result := NewCertificateBindingValidator(stubValidator{}, nil, nil).Validate(nil); result != nil {
			t.Fatalf("result = %+v, want the inner nil result", result)
		}
		mustFail(t, "nil request for a registered client",
			NewCertificateBindingValidator(stubValidator{client: clients[boundClientId]}, nil, nil).Validate(nil))
	})
}

// stubValidator authenticates client for every request, or answers nil
// without a client.
type stubValidator struct{ client *storage_models.Client }

func (s stubValidator) Validate(*http.Request) *validators_models.ClientSecretValidationResult {
	if s.client == nil {
		return nil
	}
	result := validators_models.NewClientSecretValidationResult()
	result.Client = s.client
	return result
}
