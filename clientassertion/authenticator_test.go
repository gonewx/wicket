// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package clientassertion

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/gonewx/wicket"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/validators"
	validators_impl "github.com/gonewx/wicket/validators/impl"
	validators_models "github.com/gonewx/wicket/validators/models"
)

type fixedIssuer string

func (i fixedIssuer) GetCurrent() string { return string(i) }

type clientStoreDouble map[string]*storage_models.Client

func (s clientStoreDouble) FindClientById(_ context.Context, clientId string) (*storage_models.Client, error) {
	return s[clientId], nil
}

type innerClientValidator struct {
	calls  int
	result *validators_models.ClientSecretValidationResult
}

func (v *innerClientValidator) Validate(*http.Request) *validators_models.ClientSecretValidationResult {
	v.calls++
	return v.result
}

type resourceStoreDouble struct {
	apis []*storage_models.ApiResource
}

func (s resourceStoreDouble) GetAllEnabledResources(context.Context) (*storage_models.Resources, error) {
	return nil, nil
}

func (s resourceStoreDouble) FindResourcesByScope(context.Context, []string) (*storage_models.Resources, error) {
	return nil, nil
}

func (s resourceStoreDouble) FindApiResourcesByName(_ context.Context, names []string) ([]*storage_models.ApiResource, error) {
	found := []*storage_models.ApiResource{}
	for _, api := range s.apis {
		for _, name := range names {
			if api.Name == name {
				found = append(found, api)
			}
		}
	}
	return found, nil
}

func (s resourceStoreDouble) FindApiScopesByName(context.Context, []string) ([]*storage_models.ApiScope, error) {
	return nil, nil
}

func (s resourceStoreDouble) FindIdentityResourcesByScope(context.Context, []string) ([]*storage_models.IdentityResource, error) {
	return nil, nil
}

type innerApiValidator struct {
	calls  int
	result *validators_models.ApiSecretValidationResult
}

func (v *innerApiValidator) Validate(*http.Request) *validators_models.ApiSecretValidationResult {
	v.calls++
	return v.result
}

func parserChain() validators.SecretsListParser {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return validators_impl.NewSecretParser([]validators.SecretParser{NewParser(Options{}, 100)}, logger)
}

type clientScene struct {
	f             *fixture
	key           testKey
	inner         *innerClientValidator
	authenticator *ClientAuthenticator
	registered    *storage_models.Client
	shared        *storage_models.Client
}

func newClientScene(t *testing.T) *clientScene {
	t.Helper()
	s := &clientScene{f: newFixture(Options{}), key: keyFor(t, "ES256", "k1"), inner: &innerClientValidator{}}
	s.registered = storage_models.NewClient()
	s.registered.ClientId = "assertion-client"
	s.registered.TokenEndpointAuthMethod = "private_key_jwt"
	s.registered.Jwks = keySet(t, s.key)
	s.shared = storage_models.NewClient()
	s.shared.ClientId = "secret-client"
	disabled := storage_models.NewClient()
	disabled.ClientId = "disabled-client"
	disabled.Enabled = false
	disabled.TokenEndpointAuthMethod = "private_key_jwt"
	disabled.Jwks = s.registered.Jwks
	store := clientStoreDouble{"assertion-client": s.registered, "secret-client": s.shared, "disabled-client": disabled}
	s.authenticator = NewClientAuthenticator(s.inner, parserChain(), store, s.f.verifier, fixedIssuer(testAudience), s.f.logger)
	return s
}

func (s *clientScene) assertion(t *testing.T, id string) string {
	return s.key.sign(t, "ES256", s.f.claims(id))
}

func mustFailAsInvalidClient(t *testing.T, result *validators_models.ClientSecretValidationResult) {
	t.Helper()
	if result == nil || result.Error != wicket.TokenErrorsInvalidClient || result.Client != nil || result.Description != "" {
		t.Fatalf("got %+v, want the uniform invalid_client failure", result)
	}
}

func TestClientAuthenticatorAcceptsAValidAssertion(t *testing.T) {
	s := newClientScene(t)
	result := s.authenticator.Validate(formRequest(assertionValues(s.assertion(t, "assertion-client"))))
	if result == nil || result.Error != nil || result.Client != s.registered {
		t.Fatalf("got %+v", result)
	}
	if result.Secret == nil || result.Secret.Credential != "" || result.Secret.Id != "assertion-client" || result.Secret.Type != wicket.ParsedSecretTypesJwtBearer {
		t.Fatalf("unexpected secret %+v", result.Secret)
	}
	if result.Confirmation != "" {
		t.Fatalf("unexpected confirmation %q", result.Confirmation)
	}
	if s.inner.calls != 0 || s.f.registry.callCount() != 1 {
		t.Fatalf("inner calls %d, registry calls %d", s.inner.calls, s.f.registry.callCount())
	}

	values := assertionValues(s.assertion(t, "assertion-client"))
	values.Set("client_id", "assertion-client")
	if result := s.authenticator.Validate(formRequest(values)); result.Error != nil {
		t.Fatalf("matching client_id rejected: %v", result.Error)
	}
}

func TestClientAuthenticatorRejections(t *testing.T) {
	cases := map[string]func(t *testing.T, s *clientScene) *http.Request{
		"assertion together with client_secret": func(t *testing.T, s *clientScene) *http.Request {
			values := assertionValues(s.assertion(t, "assertion-client"))
			values.Set("client_secret", "secret")
			return formRequest(values)
		},
		"assertion together with basic authorization": func(t *testing.T, s *clientScene) *http.Request {
			request := formRequest(assertionValues(s.assertion(t, "assertion-client")))
			request.Header.Set("Authorization", "bAsIc c2VjcmV0LWNsaWVudDpzZWNyZXQ=")
			return request
		},
		"assertion type alone with client_secret": func(t *testing.T, s *clientScene) *http.Request {
			return formRequest(url.Values{"client_assertion_type": {assertionType}, "client_id": {"secret-client"}, "client_secret": {"secret"}})
		},
		"assertion without its type": func(t *testing.T, s *clientScene) *http.Request {
			return formRequest(url.Values{"client_assertion": {s.assertion(t, "assertion-client")}})
		},
		"type without an assertion": func(t *testing.T, s *clientScene) *http.Request {
			return formRequest(url.Values{"client_assertion_type": {assertionType}})
		},
		"another assertion type": func(t *testing.T, s *clientScene) *http.Request {
			values := assertionValues(s.assertion(t, "assertion-client"))
			values.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:saml2-bearer")
			return formRequest(values)
		},
		"assertion type in another case": func(t *testing.T, s *clientScene) *http.Request {
			values := assertionValues(s.assertion(t, "assertion-client"))
			values.Set("client_assertion_type", "URN:ietf:params:oauth:client-assertion-type:jwt-bearer")
			return formRequest(values)
		},
		"client_id names another client": func(t *testing.T, s *clientScene) *http.Request {
			values := assertionValues(s.assertion(t, "assertion-client"))
			values.Set("client_id", "secret-client")
			return formRequest(values)
		},
		"unknown client": func(t *testing.T, s *clientScene) *http.Request {
			return formRequest(assertionValues(s.assertion(t, "nobody")))
		},
		"disabled client": func(t *testing.T, s *clientScene) *http.Request {
			return formRequest(assertionValues(s.assertion(t, "disabled-client")))
		},
		"client not registered for the method": func(t *testing.T, s *clientScene) *http.Request {
			s.shared.Jwks = s.registered.Jwks
			return formRequest(assertionValues(s.assertion(t, "secret-client")))
		},
		"assertion signed by another key": func(t *testing.T, s *clientScene) *http.Request {
			other := keyFor(t, "ES256", "k1")
			return formRequest(assertionValues(other.sign(t, "ES256", s.f.claims("assertion-client"))))
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			s := newClientScene(t)
			mustFailAsInvalidClient(t, s.authenticator.Validate(build(t, s)))
			if s.inner.calls != 0 {
				t.Fatalf("inner validator consulted %d times", s.inner.calls)
			}
			if s.f.registry.callCount() != 0 {
				t.Fatalf("registry called %d times", s.f.registry.callCount())
			}
		})
	}
}

func TestClientAuthenticatorRejectsAReplay(t *testing.T) {
	s := newClientScene(t)
	assertion := s.assertion(t, "assertion-client")
	if result := s.authenticator.Validate(formRequest(assertionValues(assertion))); result.Error != nil {
		t.Fatalf("first use: %v", result.Error)
	}
	mustFailAsInvalidClient(t, s.authenticator.Validate(formRequest(assertionValues(assertion))))
}

func TestClientAuthenticatorWithoutAnAssertion(t *testing.T) {
	s := newClientScene(t)
	inner := validators_models.NewClientSecretValidationResult()
	inner.Client = s.shared
	s.inner.result = inner
	request := formRequest(url.Values{"client_id": {"secret-client"}, "client_secret": {"secret"}})
	if got := s.authenticator.Validate(request); got != inner {
		t.Fatalf("inner result not returned as is: %+v", got)
	}

	failed := validators_models.NewClientSecretValidationResult()
	failed.Error = wicket.TokenErrorsInvalidRequest
	s.inner.result = failed
	if got := s.authenticator.Validate(request); got != failed {
		t.Fatalf("inner failure not returned as is: %+v", got)
	}

	registered := validators_models.NewClientSecretValidationResult()
	registered.Client = s.registered
	s.inner.result = registered
	mustFailAsInvalidClient(t, s.authenticator.Validate(request))
	if s.inner.calls != 3 {
		t.Fatalf("inner validator consulted %d times, want 3", s.inner.calls)
	}
}

func TestClientAuthenticatorReportsRegistryFailure(t *testing.T) {
	s := newClientScene(t)
	s.f.registry.err = errors.New("boom")
	result := s.authenticator.Validate(formRequest(assertionValues(s.assertion(t, "assertion-client"))))
	if result == nil || result.Error != ErrAuthenticationUnavailable || result.Client != nil || result.Description != "" {
		t.Fatalf("got %+v", result)
	}
}

type apiScene struct {
	f             *fixture
	key           testKey
	inner         *innerApiValidator
	authenticator *ApiAuthenticator
	api           *storage_models.ApiResource
	keySecret     *storage_models.Secret
}

func newApiScene(t *testing.T) *apiScene {
	t.Helper()
	s := &apiScene{f: newFixture(Options{}), key: keyFor(t, "ES256", "k1"), inner: &innerApiValidator{}}
	s.api = storage_models.NewApiResource()
	s.api.Name = "api1"
	s.api.Enabled = true
	shared := storage_models.NewSecret()
	shared.Value = "hash"
	s.keySecret = storage_models.NewSecret()
	s.keySecret.Type = wicket.SecretTypesJsonWebKey
	s.keySecret.Value = mustJson(t, s.key.jwk(t))
	s.api.ApiSecrets = []*storage_models.Secret{shared, s.keySecret}
	s.authenticator = NewApiAuthenticator(s.inner, parserChain(), resourceStoreDouble{apis: []*storage_models.ApiResource{s.api}},
		s.f.verifier, fixedIssuer(testAudience), s.f.clock, s.f.logger)
	return s
}

func (s *apiScene) validate(t *testing.T) *validators_models.ApiSecretValidationResult {
	t.Helper()
	return s.authenticator.Validate(formRequest(assertionValues(s.key.sign(t, "ES256", s.f.claims("api1")))))
}

func TestApiAuthenticatorAcceptsAValidAssertion(t *testing.T) {
	s := newApiScene(t)
	result := s.validate(t)
	if result == nil || result.Error != nil || result.Resource != s.api {
		t.Fatalf("got %+v", result)
	}
	wantKeys := s.f.registry.keys
	if len(wantKeys) != 1 || s.inner.calls != 0 {
		t.Fatalf("registry keys %v, inner calls %d", wantKeys, s.inner.calls)
	}

	// A JWK Set document is accepted as the entry value as well.
	s.keySecret.Value = keySet(t, s.key)
	if result := s.validate(t); result.Error != nil {
		t.Fatalf("key set entry: %v", result.Error)
	}
}

func TestApiAuthenticatorKeyEntryExpiry(t *testing.T) {
	cases := []struct {
		name   string
		expiry func(now time.Time) time.Time
		accept bool
	}{
		{"no expiration", func(time.Time) time.Time { return time.Time{} }, true},
		{"expires in one second", func(now time.Time) time.Time { return now.Add(time.Second) }, true},
		{"expires now", func(now time.Time) time.Time { return now }, false},
		{"expired one second ago", func(now time.Time) time.Time { return now.Add(-time.Second) }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newApiScene(t)
			s.keySecret.Expiration = tc.expiry(s.f.clock.Now())
			result := s.validate(t)
			if tc.accept {
				if result.Error != nil {
					t.Fatalf("rejected: %v", result.Error)
				}
				return
			}
			if result.Error != wicket.TokenErrorsInvalidClient || result.Resource != nil {
				t.Fatalf("got %+v, want invalid_client", result)
			}
			if s.f.registry.callCount() != 0 {
				t.Fatalf("registry called %d times, want 0", s.f.registry.callCount())
			}
		})
	}
}

func TestApiAuthenticatorRejections(t *testing.T) {
	t.Run("resource without a key entry", func(t *testing.T) {
		s := newApiScene(t)
		s.api.ApiSecrets = s.api.ApiSecrets[:1]
		if result := s.validate(t); result.Error != wicket.TokenErrorsInvalidClient {
			t.Fatalf("got %+v", result)
		}
	})
	t.Run("disabled resource", func(t *testing.T) {
		s := newApiScene(t)
		s.api.Enabled = false
		if result := s.validate(t); result.Error != wicket.TokenErrorsInvalidClient {
			t.Fatalf("got %+v", result)
		}
	})
	t.Run("assertion together with client_secret", func(t *testing.T) {
		s := newApiScene(t)
		values := assertionValues(s.key.sign(t, "ES256", s.f.claims("api1")))
		values.Set("client_secret", "secret")
		if result := s.authenticator.Validate(formRequest(values)); result.Error != wicket.TokenErrorsInvalidClient {
			t.Fatalf("got %+v", result)
		}
	})
	t.Run("registry failure", func(t *testing.T) {
		s := newApiScene(t)
		s.f.registry.err = errors.New("boom")
		if result := s.validate(t); result.Error != ErrAuthenticationUnavailable || result.Resource != nil {
			t.Fatalf("got %+v", result)
		}
	})
}

func TestApiAuthenticatorWithoutAnAssertionUsesTheInnerValidator(t *testing.T) {
	s := newApiScene(t)
	inner := validators_models.NewApiSecretValidationResult()
	inner.Resource = s.api
	s.inner.result = inner
	request := formRequest(url.Values{"client_id": {"api1"}, "client_secret": {"secret"}})
	if got := s.authenticator.Validate(request); got != inner || s.inner.calls != 1 {
		t.Fatalf("inner result not returned as is: %+v", got)
	}
}
