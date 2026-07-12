// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package checksession

import (
	"io"
	"mime"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	integration_common "github.com/gonewx/wicket/test/integration/common"
)

func newCheckSessionPipeline() *integration_common.WicketPipeline {
	pipeline := integration_common.NewWicketPipeline()
	pipeline.Initialize()
	return pipeline
}

func TestCheckSessionEndpointResponds(t *testing.T) {
	a := require.New(t)

	pipeline := newCheckSessionPipeline()

	response, err := pipeline.BackChannelClient.Get(pipeline.TestServer.URL + integration_common.CheckSessionEndpoint)

	a.NoError(err)
	a.NotNil(response)
	a.NotEqual(http.StatusNotFound, response.StatusCode)
}

func TestCheckSessionEndpointServesTheSessionIframeDocument(t *testing.T) {
	a := require.New(t)

	pipeline := newCheckSessionPipeline()

	response, err := pipeline.BackChannelClient.Get(pipeline.TestServer.URL + integration_common.CheckSessionEndpoint)

	a.NoError(err)
	a.Equal(http.StatusOK, response.StatusCode)

	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	a.NoError(err)
	a.Equal("text/html", mediaType)

	body, err := io.ReadAll(response.Body)
	a.NoError(err)
	a.Contains(string(body), pipeline.Options.Authentication.CheckSessionCookieName)
}
