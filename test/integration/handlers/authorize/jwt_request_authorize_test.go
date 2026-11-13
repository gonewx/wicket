// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package authorize

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/require"

	"github.com/gonewx/wicket"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/test"
	integration_common "github.com/gonewx/wicket/test/integration/common"
)

const requestObjectSymmetricJwk = `{ "kty": "oct", "use": "sig", "kid": "1", "k": "nYA-IFt8xTsdBHe9hunvizcp3Dt7f6qGqudq18kZHNtvqEGjJ9Ud-9x3kbQ-LYfLHS3xM2MpFQFg1JzT_0U_F8DI40oby4TvBDGszP664UgA8_5GjB7Flnrlsap1NlitvNpgQX3lpyTvC2zVuQ-UVsXbBDAaSBUSlnw7SE4LM8Ye2WYZrdCCXL8yAX9vIR7vf77yvNTEcBCI6y4JlvZaqMB4YKVSfygs8XqGGCHjLpE5bvI-A4ESbAUX26cVFvCeDg9pR6HK7BmwPMlO96krgtKZcXEJtUELYPys6-rbwAIdmxJxKxpgRpt0FRv_9fm6YPwG7QivYBX-vRwaodL1TA", "alg": "HS256"}`

type requestObjectFixture struct {
	pipeline *integration_common.WicketPipeline
	client   *storage_models.Client
	rsaKey   *rsa.PrivateKey
	rsaJwk   jwk.Key
}

func newRequestObjectFixture(t *testing.T) *requestObjectFixture {
	t.Helper()

	pipeline := integration_common.NewWicketPipeline()

	testcert := integration_common.NewTestCert()
	certKeyDer, err := testcert.Load()
	require.NoError(t, err)
	certJwk, err := testcert.LoadKey()
	require.NoError(t, err)
	certJwkJson, err := json.Marshal(certJwk)
	require.NoError(t, err)

	rsaKey, err := testcert.CreateRsaSecurityKey()
	require.NoError(t, err)
	rsaJwk, err := jwk.Import(rsaKey)
	require.NoError(t, err)
	require.NoError(t, jwk.AssignKeyID(rsaJwk))
	require.NoError(t, rsaJwk.Set(jwk.AlgorithmKey, jwa.RS256()))
	rsaJwkJson, err := json.Marshal(rsaJwk)
	require.NoError(t, err)

	client := storage_models.NewClient()
	client.ClientId = "client"
	client.Enabled = true
	client.RequireRequestObject = true
	client.RedirectUris = []string{"https://client/callback"}

	secretCert := storage_models.NewSecret()
	secretCert.Type = wicket.SecretTypesX509CertificateBase64
	secretCert.Value = base64.StdEncoding.EncodeToString(certKeyDer)

	secretSymmetric := storage_models.NewSecret()
	secretSymmetric.Type = wicket.SecretTypesJsonWebKey
	secretSymmetric.Value = requestObjectSymmetricJwk

	secretRsa := storage_models.NewSecret()
	secretRsa.Type = wicket.SecretTypesJsonWebKey
	secretRsa.Value = string(rsaJwkJson)

	secretCertJwk := storage_models.NewSecret()
	secretCertJwk.Type = wicket.SecretTypesJsonWebKey
	secretCertJwk.Value = string(certJwkJson)

	client.ClientSecrets = []*storage_models.Secret{secretCert, secretSymmetric, secretRsa, secretCertJwk}

	require.NoError(t, client.SetAllowedGrantTypes(wicket.GrantTypesImplicit))
	client.AllowedScopes = []string{"openid", "profile", "api1", "api2"}

	pipeline.Clients = []*storage_models.Client{client}

	user := test.NewTestUser()
	user.SubjectId = "bob"
	user.Username = "bob"
	pipeline.Users = append(pipeline.Users, user)

	pipeline.IdentityScopes = append(pipeline.IdentityScopes,
		storage_models.IdentityResourcesOpenId(),
		storage_models.IdentityResourcesProfile(),
	)

	apiResource := storage_models.NewApiResource()
	apiResource.Name = "api1"
	apiResource.Scopes = []string{"api1", "api2"}
	pipeline.ApiResources = append(pipeline.ApiResources, apiResource)

	for _, name := range []string{"api1", "api2"} {
		scope := storage_models.NewApiScope()
		scope.Name = name
		pipeline.ApiScopes = append(pipeline.ApiScopes, scope)
	}

	pipeline.Initialize()

	return &requestObjectFixture{
		pipeline: pipeline,
		client:   client,
		rsaKey:   rsaKey.(*rsa.PrivateKey),
		rsaJwk:   rsaJwk,
	}
}

func (f *requestObjectFixture) requestClaims() map[string]any {
	return map[string]any{
		"client_id":     f.client.ClientId,
		"response_type": "id_token",
		"scope":         "openid profile",
		"state":         "123state",
		"nonce":         "123nonce",
		"redirect_uri":  "https://client/callback",
		"acr_values":    "acr_1 acr_2 tenant:tenant_value idp:idp_value",
		"login_hint":    "login_hint_value",
		"display":       "popup",
		"ui_locales":    "ui_locale_value",
		"foo":           "123foo",
	}
}

// signRequestObject signs an authorization request object over the given key.
func signRequestObject(t *testing.T, issuer string, audience string, signingKey jwk.Key, algorithm jwa.SignatureAlgorithm, requestClaims map[string]any, typHeader string) string {
	t.Helper()

	token := jwt.New()
	require.NoError(t, token.Set(jwt.IssuerKey, issuer))
	require.NoError(t, token.Set(jwt.AudienceKey, audience))
	for name, value := range requestClaims {
		require.NoError(t, token.Set(name, value))
	}

	headers := jws.NewHeaders()
	require.NoError(t, headers.Set(jws.TypeKey, typHeader))
	if kid, ok := signingKey.KeyID(); ok && kid != "" {
		require.NoError(t, headers.Set(jws.KeyIDKey, kid))
	}

	signed, err := jwt.Sign(token, jwt.WithKey(algorithm, signingKey, jws.WithProtectedHeaders(headers)))
	require.NoError(t, err)
	return string(signed)
}

func (f *requestObjectFixture) certSigningKey(t *testing.T) jwk.Key {
	t.Helper()
	credential, err := integration_common.NewTestCert().LoadSigningCredentials()
	require.NoError(t, err)
	key, err := jwk.Import(credential.Key)
	require.NoError(t, err)
	require.NoError(t, jwk.AssignKeyID(key))
	return key
}

func (f *requestObjectFixture) symmetricSigningKey(t *testing.T) jwk.Key {
	t.Helper()
	key, err := jwk.ParseKey([]byte(requestObjectSymmetricJwk))
	require.NoError(t, err)
	return key
}

func (f *requestObjectFixture) authorize(t *testing.T, requestJwt string, extra url.Values) {
	t.Helper()

	if extra == nil {
		extra = url.Values{}
	}
	if requestJwt != "" {
		extra.Set("request", requestJwt)
	}

	routePath, err := f.pipeline.CreateAuthorizeUrl(&integration_common.AuthorizeUrl{
		ClientId:     f.client.ClientId,
		ResponseType: "id_token",
		Extra:        extra,
	})
	require.NoError(t, err)

	_, err = f.pipeline.BrowserClient.Get(routePath.String())
	require.NoError(t, err)
}

func assertRequestObjectLoginRequest(t *testing.T, fixture *requestObjectFixture) {
	a := require.New(t)

	loginRequest := fixture.pipeline.LoginRequest
	a.NotNil(loginRequest)
	a.Equal(fixture.client.ClientId, loginRequest.Client.ClientId)
	a.Equal("popup", loginRequest.DisplayMode)
	a.Equal("ui_locale_value", loginRequest.UiLocales)
	a.Equal("idp_value", loginRequest.IdP)
	a.Equal("tenant_value", loginRequest.Tenant)
	a.Equal("login_hint_value", loginRequest.LoginHint)
	a.ElementsMatch([]string{"acr_1", "acr_2"}, loginRequest.AcrValues)
	a.Equal("123foo", loginRequest.Parameters.Get("foo"))

	fooValues := 0
	for _, claim := range loginRequest.RequestObjectValues {
		if claim.Type == "foo" && claim.Value == "123foo" {
			fooValues++
		}
	}
	a.Equal(1, fooValues)
}

func TestRequestObjectRequiredButMissingFails(t *testing.T) {
	a := require.New(t)

	fixture := newRequestObjectFixture(t)

	routePath, err := fixture.pipeline.CreateAuthorizeUrl(&integration_common.AuthorizeUrl{
		ClientId:     fixture.client.ClientId,
		ResponseType: "id_token",
		Scope:        "openid profile",
		State:        "123state",
		Nonce:        "123nonce",
		RedirectUri:  "https://client/callback",
	})
	a.NoError(err)

	_, err = fixture.pipeline.BrowserClient.Get(routePath.String())
	a.NoError(err)

	a.NotNil(fixture.pipeline.ErrorMessage)
	a.Equal("invalid_request", fixture.pipeline.ErrorMessage.Error)
	a.Nil(fixture.pipeline.LoginRequest)
}

func TestValidRequestObjectSignatures(t *testing.T) {
	for name, sign := range map[string]func(*testing.T, *requestObjectFixture) string{
		"x509 certificate key": func(t *testing.T, f *requestObjectFixture) string {
			return signRequestObject(t, f.client.ClientId, f.pipeline.TestServer.URL, f.certSigningKey(t), jwa.RS256(), f.requestClaims(), "JWT")
		},
		"symmetric jwk": func(t *testing.T, f *requestObjectFixture) string {
			return signRequestObject(t, f.client.ClientId, f.pipeline.TestServer.URL, f.symmetricSigningKey(t), jwa.HS256(), f.requestClaims(), "JWT")
		},
		"rsa jwk": func(t *testing.T, f *requestObjectFixture) string {
			return signRequestObject(t, f.client.ClientId, f.pipeline.TestServer.URL, f.rsaJwk, jwa.RS256(), f.requestClaims(), "JWT")
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newRequestObjectFixture(t)
			fixture.authorize(t, sign(t, fixture), nil)
			assertRequestObjectLoginRequest(t, fixture)
		})
	}
}

func TestQueryParametersOutsideTheRequestObjectAreMergedButNotTrusted(t *testing.T) {
	a := require.New(t)

	fixture := newRequestObjectFixture(t)

	requestClaims := fixture.requestClaims()
	delete(requestClaims, "state")
	delete(requestClaims, "nonce")

	requestJwt := signRequestObject(t, fixture.client.ClientId, fixture.pipeline.TestServer.URL, fixture.certSigningKey(t), jwa.RS256(), requestClaims, "JWT")

	fixture.authorize(t, requestJwt, url.Values{"state": {"state"}, "nonce": {"nonce"}})

	loginRequest := fixture.pipeline.LoginRequest
	a.NotNil(loginRequest)
	a.Equal("state", loginRequest.Parameters.Get("state"))
	a.Equal("nonce", loginRequest.Parameters.Get("nonce"))
	for _, claim := range loginRequest.RequestObjectValues {
		a.NotEqual("state", claim.Type)
		a.NotEqual("nonce", claim.Type)
	}
}

func TestStrictRequestObjectTypeValidation(t *testing.T) {
	t.Run("authorization-request typ passes strict validation", func(t *testing.T) {
		a := require.New(t)

		fixture := newRequestObjectFixture(t)
		fixture.pipeline.Options.StrictJarValidation = true

		requestJwt := signRequestObject(t, fixture.client.ClientId, fixture.pipeline.TestServer.URL, fixture.rsaJwk, jwa.RS256(), fixture.requestClaims(), "oauth-authz-req+jwt")
		fixture.authorize(t, requestJwt, nil)

		a.NotNil(fixture.pipeline.LoginRequest)
	})

	t.Run("plain typ fails strict validation", func(t *testing.T) {
		a := require.New(t)

		fixture := newRequestObjectFixture(t)
		fixture.pipeline.Options.StrictJarValidation = true

		requestJwt := signRequestObject(t, fixture.client.ClientId, fixture.pipeline.TestServer.URL, fixture.rsaJwk, jwa.RS256(), fixture.requestClaims(), "JWT")
		fixture.authorize(t, requestJwt, nil)

		a.NotNil(fixture.pipeline.ErrorMessage)
		a.Equal("invalid_request_object", fixture.pipeline.ErrorMessage.Error)
		a.Nil(fixture.pipeline.LoginRequest)
	})
}

func TestComplexRequestObjectValuesSurviveTheRoundTrip(t *testing.T) {
	a := require.New(t)

	fixture := newRequestObjectFixture(t)

	type inner struct {
		Bar string `json:"bar"`
	}
	type outer struct {
		Foo *inner `json:"foo"`
		Baz string `json:"baz"`
	}
	payload := outer{Foo: &inner{Bar: "bar"}, Baz: "baz"}
	payloadJson, err := json.Marshal(&payload)
	a.NoError(err)

	requestClaims := fixture.requestClaims()
	requestClaims["someObj"] = string(payloadJson)
	requestClaims["someArr"] = []string{"a", "b", "c"}

	requestJwt := signRequestObject(t, fixture.client.ClientId, fixture.pipeline.TestServer.URL, fixture.certSigningKey(t), jwa.RS256(), requestClaims, "JWT")
	fixture.authorize(t, requestJwt, nil)

	loginRequest := fixture.pipeline.LoginRequest
	a.NotNil(loginRequest)

	roundTripped := outer{}
	a.NoError(json.Unmarshal([]byte(loginRequest.Parameters.Get("someObj")), &roundTripped))
	a.EqualValues(payload, roundTripped)

	arrValues := loginRequest.Parameters["someArr"]
	a.Len(arrValues, 3)
}

func TestRequestObjectRejections(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate    func(*testing.T, *requestObjectFixture) (jwt string, extra url.Values)
		wantError string
	}{
		"missing client_id in the query": {
			mutate: func(t *testing.T, f *requestObjectFixture) (string, url.Values) {
				requestClaims := f.requestClaims()
				delete(requestClaims, "client_id")
				signed := signRequestObject(t, f.client.ClientId, f.pipeline.TestServer.URL, f.certSigningKey(t), jwa.RS256(), requestClaims, "JWT")
				return signed, url.Values{"omit_client_id": {"1"}}
			},
			wantError: "invalid_request",
		},
		"missing client_id inside the request object": {
			mutate: func(t *testing.T, f *requestObjectFixture) (string, url.Values) {
				requestClaims := f.requestClaims()
				delete(requestClaims, "client_id")
				return signRequestObject(t, f.client.ClientId, f.pipeline.TestServer.URL, f.certSigningKey(t), jwa.RS256(), requestClaims, "JWT"), nil
			},
			wantError: "invalid_request_object",
		},
		"wrong audience": {
			mutate: func(t *testing.T, f *requestObjectFixture) (string, url.Values) {
				return signRequestObject(t, f.client.ClientId, "invalid", f.certSigningKey(t), jwa.RS256(), f.requestClaims(), "JWT"), nil
			},
			wantError: "invalid_request_object",
		},
		"issuer does not match the client": {
			mutate: func(t *testing.T, f *requestObjectFixture) (string, url.Values) {
				return signRequestObject(t, "invalid", f.pipeline.TestServer.URL, f.certSigningKey(t), jwa.RS256(), f.requestClaims(), "JWT"), nil
			},
			wantError: "invalid_request_object",
		},
		"request parameter nested inside the request object": {
			mutate: func(t *testing.T, f *requestObjectFixture) (string, url.Values) {
				requestClaims := f.requestClaims()
				requestClaims["request"] = "request"
				return signRequestObject(t, f.client.ClientId, f.pipeline.TestServer.URL, f.certSigningKey(t), jwa.RS256(), requestClaims, "JWT"), nil
			},
			wantError: "invalid_request_object",
		},
	} {
		t.Run(name, func(t *testing.T) {
			a := require.New(t)

			fixture := newRequestObjectFixture(t)
			requestJwt, extra := tc.mutate(t, fixture)

			if extra != nil && extra.Get("omit_client_id") != "" {
				// Issue the authorize request without any client_id parameter.
				u, err := fixture.pipeline.CreateAuthorizeUrl(&integration_common.AuthorizeUrl{
					ResponseType: "id_token",
					Extra:        url.Values{"request": {requestJwt}},
				})
				a.NoError(err)
				_, err = fixture.pipeline.BrowserClient.Get(u.String())
				a.NoError(err)
			} else {
				fixture.authorize(t, requestJwt, nil)
			}

			a.NotNil(fixture.pipeline.ErrorMessage)
			a.Equal(tc.wantError, fixture.pipeline.ErrorMessage.Error)
			a.Nil(fixture.pipeline.LoginRequest)
		})
	}
}

func TestRequestUriFetchesTheRequestObject(t *testing.T) {
	a := require.New(t)

	fixture := newRequestObjectFixture(t)
	fixture.pipeline.Options.Endpoints.EnableJwtRequestUri = true

	requestJwt := signRequestObject(t, fixture.client.ClientId, fixture.pipeline.TestServer.URL, fixture.certSigningKey(t), jwa.RS256(), fixture.requestClaims(), "JWT")

	objectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(requestJwt))
	}))
	t.Cleanup(objectServer.Close)

	routePath, err := fixture.pipeline.CreateAuthorizeUrl(&integration_common.AuthorizeUrl{
		ClientId:     fixture.client.ClientId,
		ResponseType: "id_token",
		Extra:        url.Values{"request_uri": {objectServer.URL + "/request.jwt"}},
	})
	a.NoError(err)

	_, err = fixture.pipeline.BrowserClient.Get(routePath.String())
	a.NoError(err)

	assertRequestObjectLoginRequest(t, fixture)
}

func TestRequestUriFetchFailureIsRejected(t *testing.T) {
	a := require.New(t)

	fixture := newRequestObjectFixture(t)
	fixture.pipeline.Options.Endpoints.EnableJwtRequestUri = true

	objectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(objectServer.Close)

	routePath, err := fixture.pipeline.CreateAuthorizeUrl(&integration_common.AuthorizeUrl{
		ClientId:     fixture.client.ClientId,
		ResponseType: "id_token",
		Extra:        url.Values{"request_uri": {objectServer.URL + "/request.jwt"}},
	})
	a.NoError(err)

	_, err = fixture.pipeline.BrowserClient.Get(routePath.String())
	a.NoError(err)

	a.NotNil(fixture.pipeline.ErrorMessage)
	a.NotEmpty(fixture.pipeline.ErrorMessage.Error)
	a.Nil(fixture.pipeline.LoginRequest)
}
