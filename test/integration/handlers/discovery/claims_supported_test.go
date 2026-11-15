// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package discovery

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	storage_models "github.com/gonewx/wicket/storage/models"
	integration_common "github.com/gonewx/wicket/test/integration/common"
)

// The claims of the identity resources are advertised under claims_supported
// (OpenID Connect Discovery 1.0 §3), and no key of the document carries a dot.
func TestClaimsSupportedKey(t *testing.T) {
	a := require.New(t)

	pipeline := integration_common.NewWicketPipeline()
	pipeline.IdentityScopes = append(pipeline.IdentityScopes,
		storage_models.IdentityResourcesOpenId(),
		storage_models.IdentityResourcesProfile(),
	)
	pipeline.Initialize()

	data := getBody(t, pipeline, integration_common.DiscoveryEndpoint)

	claims := gjson.Get(data, "claims_supported")
	a.True(claims.IsArray(), "claims_supported missing: %s", data)
	values := make([]string, 0)
	for _, value := range claims.Array() {
		values = append(values, value.String())
	}
	a.Contains(values, "sub")
	a.Contains(values, "name")

	gjson.Parse(data).ForEach(func(key, _ gjson.Result) bool {
		a.False(strings.Contains(key.String(), "."), "key %q", key.String())
		return true
	})
}
