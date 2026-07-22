// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package discovery

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	"github.com/gonewx/wicket/models"
	integration_common "github.com/gonewx/wicket/test/integration/common"
	"github.com/gonewx/wicket/tokens"
)

func newDiscoveryPipeline() *integration_common.WicketPipeline {
	pipeline := integration_common.NewWicketPipeline()
	pipeline.Initialize()
	return pipeline
}

func ecdsaCredential(t *testing.T, curve elliptic.Curve, algorithm jwa.SignatureAlgorithm) *tokens.SigningCredentials {
	t.Helper()

	raw, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)

	key, err := jwk.Import(raw)
	require.NoError(t, err)
	require.NoError(t, jwk.AssignKeyID(key))

	kid, _ := key.KeyID()
	credential, err := tokens.NewSigningCredentials(raw, tokens.WithAlgorithm(algorithm.String()), tokens.WithKid(kid))
	require.NoError(t, err)
	return credential
}

func getBody(t *testing.T, pipeline *integration_common.WicketPipeline, path string) string {
	t.Helper()

	response, err := pipeline.BackChannelClient.Get(pipeline.TestServer.URL + path)
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	_ = response.Body.Close()
	return string(body)
}

func TestIssuerReflectsTheServerOrigin(t *testing.T) {
	a := require.New(t)

	pipeline := newDiscoveryPipeline()

	data := getBody(t, pipeline, integration_common.DiscoveryEndpoint)

	a.Equal(pipeline.TestServer.URL, gjson.Get(data, "issuer").String())
}

func TestIssuerPreservedWhenLowerCasingDisabled(t *testing.T) {
	a := require.New(t)

	pipeline := newDiscoveryPipeline()
	pipeline.Options.LowerCaseIssuerUri = false

	data := getBody(t, pipeline, integration_common.DiscoveryEndpoint)

	a.Equal(pipeline.TestServer.URL, gjson.Get(data, "issuer").String())
}

func TestSigningAlgorithmsSupportedMatchTheRegisteredKeys(t *testing.T) {
	a := require.New(t)

	pipeline := integration_common.NewWicketPipeline()
	pipeline.Initialize()
	pipeline.AddSigningCredential(ecdsaCredential(t, elliptic.P256(), jwa.ES256()))

	data := getBody(t, pipeline, integration_common.DiscoveryEndpoint)

	algorithms := gjson.Get(data, "id_token_signing_alg_values_supported").Array()
	values := make([]string, 0, len(algorithms))
	for _, algorithm := range algorithms {
		values = append(values, algorithm.String())
	}
	a.Len(values, 2)
	a.Contains(values, jwa.RS256().String())
	a.Contains(values, jwa.ES256().String())
}

func TestDiscoveryDocumentIsValidJson(t *testing.T) {
	a := require.New(t)

	pipeline := newDiscoveryPipeline()

	data := getBody(t, pipeline, integration_common.DiscoveryEndpoint)

	var parsed any
	a.NoError(json.Unmarshal([]byte(data), &parsed))
}

func TestJwksEllipticCurveEntriesCarryCrv(t *testing.T) {
	a := require.New(t)

	pipeline := integration_common.NewWicketPipeline()
	pipeline.Initialize()
	pipeline.AddSigningCredential(ecdsaCredential(t, elliptic.P256(), jwa.ES256()))

	data := getBody(t, pipeline, integration_common.DiscoveryKeysEndpoint)

	keys := gjson.Get(data, "keys").Array()
	a.Len(keys, 2)

	found := false
	for _, key := range keys {
		if gjson.Get(key.String(), "kty").String() == "EC" {
			found = true
			a.Equal(jwa.P256().String(), gjson.Get(key.String(), "crv").String())
		}
	}
	a.True(found)
}

func TestJwksEntriesCarryAlg(t *testing.T) {
	a := require.New(t)

	pipeline := newDiscoveryPipeline()

	data := getBody(t, pipeline, integration_common.DiscoveryKeysEndpoint)

	keys := gjson.Get(data, "keys").Array()
	a.NotEmpty(keys)
	a.Equal(jwa.RS256().String(), gjson.Get(keys[0].String(), "alg").String())
}

func TestJwksEcdsaKeysAreParsable(t *testing.T) {
	a := require.New(t)

	curves := []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()}
	algorithms := []jwa.SignatureAlgorithm{jwa.ES256(), jwa.ES384(), jwa.ES512()}

	for i, curve := range curves {
		pipeline := integration_common.NewWicketPipeline()
		pipeline.Initialize()
		credential := ecdsaCredential(t, curve, algorithms[i])
		pipeline.AddSigningCredential(credential)

		data := getBody(t, pipeline, integration_common.DiscoveryKeysEndpoint)

		jwks, err := jwk.Parse([]byte(data))
		a.NoError(err)

		matchingKey, ok := jwks.LookupKeyID(credential.Kid)
		a.True(ok)

		var parsedKey any
		a.NoError(jwk.Export(matchingKey, &parsedKey))
		a.IsType(&ecdsa.PublicKey{}, parsedKey)
	}
}

func TestJwksKeysWithDifferentAlgorithmsKeepTheirOwnAlg(t *testing.T) {
	a := require.New(t)

	pipeline := integration_common.NewWicketPipeline()
	pipeline.Initialize()

	credential := ecdsaCredential(t, elliptic.P256(), jwa.ES256())
	pipeline.AddSigningCredential(credential)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	a.NoError(err)
	pipeline.AddValidationKey([]*models.SecurityKeyInfo{
		{Key: rsaKey, SigningAlgorithm: jwa.RS256().String()},
	})

	data := getBody(t, pipeline, integration_common.DiscoveryKeysEndpoint)

	jwks, err := jwk.Parse([]byte(data))
	a.NoError(err)

	matchingKey, ok := jwks.LookupKeyID(credential.Kid)
	a.True(ok)
	alg, _ := matchingKey.Algorithm()
	a.Equal(jwa.ES256().String(), alg.String())

	rsaJwk, err := jwk.Import(rsaKey)
	a.NoError(err)
	a.NoError(jwk.AssignKeyID(rsaJwk))

	rsaKid, _ := rsaJwk.KeyID()
	matchingKey, ok = jwks.LookupKeyID(rsaKid)
	a.True(ok)
	alg, _ = matchingKey.Algorithm()
	a.Equal(jwa.RS256().String(), alg.String())
}
