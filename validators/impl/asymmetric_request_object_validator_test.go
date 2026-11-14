// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/gonewx/wicket"
	config_options "github.com/gonewx/wicket/config/options"
	storage_models "github.com/gonewx/wicket/storage/models"
	validators_contexts "github.com/gonewx/wicket/validators/contexts"
	validators_models "github.com/gonewx/wicket/validators/models"
)

const (
	requestObjectTestIssuer = "https://server.example"
	requestObjectTestClient = "client"
)

type fixedIssuer string

func (i fixedIssuer) GetCurrent() string { return string(i) }

// requestObjectKeys holds the keys of a test client and its secrets.
type requestObjectKeys struct {
	rsa       *rsa.PrivateKey
	ec        *ecdsa.PrivateKey
	symmetric []byte
	secrets   []*storage_models.Secret
}

func jsonWebKeySecret(t *testing.T, key jwk.Key) *storage_models.Secret {
	t.Helper()
	raw, err := json.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	secret := storage_models.NewSecret()
	secret.Type = wicket.SecretTypesJsonWebKey
	secret.Value = string(raw)
	return secret
}

func newRequestObjectKeys(t *testing.T, asymmetric bool) *requestObjectKeys {
	t.Helper()
	keys := &requestObjectKeys{symmetric: make([]byte, 64)}
	if _, err := rand.Read(keys.symmetric); err != nil {
		t.Fatal(err)
	}
	symmetric, err := jwk.Import(keys.symmetric)
	if err != nil {
		t.Fatal(err)
	}
	// The symmetric key names its own algorithm; jwx then verifies with
	// that algorithm whatever the header says.
	_ = symmetric.Set(jwk.KeyIDKey, "sym")
	_ = symmetric.Set(jwk.AlgorithmKey, jwa.HS256())
	keys.secrets = append(keys.secrets, jsonWebKeySecret(t, symmetric))
	if !asymmetric {
		return keys
	}

	keys.rsa, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaPublic, err := jwk.Import(keys.rsa.Public())
	if err != nil {
		t.Fatal(err)
	}
	_ = rsaPublic.Set(jwk.KeyIDKey, "rsa")
	keys.secrets = append(keys.secrets, jsonWebKeySecret(t, rsaPublic))

	keys.ec, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecPublic, err := jwk.Import(keys.ec.Public())
	if err != nil {
		t.Fatal(err)
	}
	_ = ecPublic.Set(jwk.KeyIDKey, "ec")
	keys.secrets = append(keys.secrets, jsonWebKeySecret(t, ecPublic))
	return keys
}

func (k *requestObjectKeys) client() *storage_models.Client {
	client := storage_models.NewClient()
	client.ClientId = requestObjectTestClient
	client.ClientSecrets = slices.Clone(k.secrets)
	return client
}

func requestObjectClaims(t *testing.T) jwt.Token {
	t.Helper()
	token, err := jwt.NewBuilder().
		Issuer(requestObjectTestClient).
		Audience([]string{requestObjectTestIssuer}).
		Expiration(time.Now().Add(time.Minute)).
		Claim("client_id", requestObjectTestClient).
		Claim("scope", "openid").
		Build()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func signedRequestObject(t *testing.T, algorithm jwa.SignatureAlgorithm, key any, kid string) string {
	t.Helper()
	signingKey, err := jwk.Import(key)
	if err != nil {
		t.Fatal(err)
	}
	_ = signingKey.Set(jwk.KeyIDKey, kid)
	signed, err := jwt.Sign(requestObjectClaims(t), jwt.WithKey(algorithm, signingKey))
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}

func rawSegment(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// disguisedRequestObject declares RS256 in its header but carries an HMAC
// SHA-256 signature made with the client's symmetric key.
func disguisedRequestObject(t *testing.T, symmetric []byte, kid string) string {
	t.Helper()
	header := map[string]any{"alg": "RS256", "typ": "JWT"}
	if kid != "" {
		header["kid"] = kid
	}
	claims := map[string]any{
		"iss":       requestObjectTestClient,
		"aud":       requestObjectTestIssuer,
		"exp":       time.Now().Add(time.Minute).Unix(),
		"client_id": requestObjectTestClient,
		"scope":     "openid",
	}
	input := rawSegment(t, header) + "." + rawSegment(t, claims)
	mac := hmac.New(sha256.New, symmetric)
	mac.Write([]byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func headerOnlyRequestObject(t *testing.T, header any) string {
	t.Helper()
	return rawSegment(t, header) + "." + rawSegment(t, map[string]any{"iss": requestObjectTestClient}) + ".c2ln"
}

func newInnerRequestObjectValidator() *JwtRequestValidator {
	return NewJwtRequestValidator(config_options.NewWicketOptions(), fixedIssuer(requestObjectTestIssuer), slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// countingRequestObjectValidator records the contexts it is handed.
type countingRequestObjectValidator struct {
	calls   int
	clients []*storage_models.Client
}

func (c *countingRequestObjectValidator) Validate(ctx *validators_contexts.JwtRequestValidationContext) (*validators_models.JwtRequestValidationResult, error) {
	c.calls++
	c.clients = append(c.clients, ctx.Client)
	return validators_models.NewJwtRequestValidationResult(), nil
}

func validateRequestObject(validator interface {
	Validate(*validators_contexts.JwtRequestValidationContext) (*validators_models.JwtRequestValidationResult, error)
}, client *storage_models.Client, token string) (*validators_models.JwtRequestValidationResult, error) {
	return validator.Validate(&validators_contexts.JwtRequestValidationContext{Client: client, JwtTokenString: token})
}

func TestAsymmetricRequestObjectValidatorAcceptsAsymmetricSignatures(t *testing.T) {
	keys := newRequestObjectKeys(t, true)
	decorator := NewAsymmetricRequestObjectValidator(newInnerRequestObjectValidator())
	cases := []struct {
		name      string
		algorithm jwa.SignatureAlgorithm
		key       any
		kid       string
	}{
		{"RS256", jwa.RS256(), keys.rsa, "rsa"},
		{"PS256", jwa.PS256(), keys.rsa, "rsa"},
		{"ES256", jwa.ES256(), keys.ec, "ec"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := validateRequestObject(decorator, keys.client(), signedRequestObject(t, tc.algorithm, tc.key, tc.kid))
			if err != nil || result == nil || result.Error != nil {
				t.Fatalf("Validate = %v, %v; want acceptance", result, err)
			}
		})
	}
}

func TestAsymmetricRequestObjectValidatorRefusals(t *testing.T) {
	keys := newRequestObjectKeys(t, true)
	symmetricOnly := newRequestObjectKeys(t, false)

	cases := []struct {
		name   string
		client *storage_models.Client
		token  func(t *testing.T) string
		// reachesInner tells whether the header check lets the request
		// object through to the wrapped validator.
		reachesInner bool
	}{
		{"HS256", keys.client(), func(t *testing.T) string { return signedRequestObject(t, jwa.HS256(), keys.symmetric, "sym") }, false},
		{"HS384", keys.client(), func(t *testing.T) string { return signedRequestObject(t, jwa.HS384(), keys.symmetric, "sym") }, false},
		{"HS512", keys.client(), func(t *testing.T) string { return signedRequestObject(t, jwa.HS512(), keys.symmetric, "sym") }, false},
		{"none", keys.client(), func(t *testing.T) string { return headerOnlyRequestObject(t, map[string]any{"alg": "none"}) }, false},
		{"missing alg", keys.client(), func(t *testing.T) string { return headerOnlyRequestObject(t, map[string]any{"typ": "JWT"}) }, false},
		{"header not base64url", keys.client(), func(*testing.T) string { return "!!!.e30.c2ln" }, false},
		{"header not JSON", keys.client(), func(*testing.T) string {
			return base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".e30.c2ln"
		}, false},
		{"case variant alg member", keys.client(), func(*testing.T) string {
			return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","Alg":"RS256"}`)) + ".e30.c2ln"
		}, false},
		{"case variant only", keys.client(), func(*testing.T) string {
			return base64.RawURLEncoding.EncodeToString([]byte(`{"ALG":"RS256"}`)) + ".e30.c2ln"
		}, false},
		{"duplicate alg member", keys.client(), func(*testing.T) string {
			return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","alg":"RS256"}`)) + ".e30.c2ln"
		}, false},
		{"header alg not a string", keys.client(), func(t *testing.T) string { return headerOnlyRequestObject(t, map[string]any{"alg": 256}) }, false},
		{"JSON serialization", keys.client(), func(t *testing.T) string {
			return `{"payload":"e30","signatures":[{"protected":"` + rawSegment(t, map[string]any{"alg": "RS256"}) + `","signature":"c2ln"}]}`
		}, false},
		{"multiple signatures", keys.client(), func(t *testing.T) string {
			protected := rawSegment(t, map[string]any{"alg": "RS256"})
			return `{"payload":"e30","signatures":[{"protected":"` + protected + `","signature":"c2ln"},{"protected":"` + protected + `","signature":"c2ln"}]}`
		}, false},
		{"two segments", keys.client(), func(t *testing.T) string { return rawSegment(t, map[string]any{"alg": "RS256"}) + ".e30" }, false},
		{"disguised HMAC under RS256", keys.client(), func(t *testing.T) string { return disguisedRequestObject(t, keys.symmetric, "sym") }, true},
		{"disguised HMAC without kid", keys.client(), func(t *testing.T) string { return disguisedRequestObject(t, keys.symmetric, "") }, true},
		{"no asymmetric key", symmetricOnly.client(), func(t *testing.T) string { return disguisedRequestObject(t, symmetricOnly.symmetric, "sym") }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token := tc.token(t)
			result, err := validateRequestObject(NewAsymmetricRequestObjectValidator(newInnerRequestObjectValidator()), tc.client, token)
			if err == nil || result != nil {
				t.Fatalf("Validate = %v, %v; want (nil, error)", result, err)
			}
			if strings.Contains(err.Error(), token) {
				t.Fatal("the error text carries the request object")
			}

			counting := &countingRequestObjectValidator{}
			_, _ = validateRequestObject(NewAsymmetricRequestObjectValidator(counting), tc.client, token)
			if reached := counting.calls > 0; reached != tc.reachesInner {
				t.Fatalf("inner reached = %v, want %v", reached, tc.reachesInner)
			}
		})
	}
}

// TestAsymmetricRequestObjectValidatorStrippingDecides proves the disguised
// request object is refused because of the stripped symmetric keys: the
// wrapped validator alone accepts it.
func TestAsymmetricRequestObjectValidatorStrippingDecides(t *testing.T) {
	keys := newRequestObjectKeys(t, true)
	token := disguisedRequestObject(t, keys.symmetric, "sym")

	result, err := validateRequestObject(newInnerRequestObjectValidator(), keys.client(), token)
	if err != nil || result == nil {
		t.Fatalf("wrapped validator alone: %v, %v; want acceptance, otherwise the disguise case proves nothing", result, err)
	}
	if _, err := validateRequestObject(NewAsymmetricRequestObjectValidator(newInnerRequestObjectValidator()), keys.client(), token); err == nil {
		t.Fatal("decorator accepted the disguised request object")
	}
}

func TestAsymmetricRequestObjectValidatorLeavesTheClientUntouched(t *testing.T) {
	keys := newRequestObjectKeys(t, true)
	client := keys.client()
	original := slices.Clone(client.ClientSecrets)
	counting := &countingRequestObjectValidator{}

	_, err := validateRequestObject(NewAsymmetricRequestObjectValidator(counting), client, signedRequestObject(t, jwa.RS256(), keys.rsa, "rsa"))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !slices.Equal(client.ClientSecrets, original) {
		t.Fatal("the client's secrets were modified")
	}
	if counting.calls != 1 || counting.clients[0] == client {
		t.Fatal("the wrapped validator was not handed a copy of the client")
	}
	handed := counting.clients[0]
	if len(handed.ClientSecrets) != 2 || handed.ClientId != client.ClientId {
		t.Fatalf("handed client has %d secrets, want the 2 asymmetric ones", len(handed.ClientSecrets))
	}
	if handed.GetKeys().Len() != 2 {
		t.Fatal("handed client lost an asymmetric key")
	}
	for i := 0; i < handed.GetKeys().Len(); i++ {
		key, _ := handed.GetKeys().Key(i)
		if key.KeyType() == jwa.OctetSeq() {
			t.Fatal("handed client still carries a symmetric key")
		}
	}
}

func TestAsymmetricRequestObjectSigningAlgorithms(t *testing.T) {
	want := []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}
	got := AsymmetricRequestObjectSigningAlgorithms()
	if !slices.Equal(got, want) {
		t.Fatalf("algorithms = %v, want %v", got, want)
	}
	got[0] = "HS256"
	if AsymmetricRequestObjectSigningAlgorithms()[0] != "RS256" {
		t.Fatal("the returned list aliases the table")
	}
}
