// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package endsession

import (
	"net/http"
	urlpkg "net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	integration_common "github.com/gonewx/wicket/test/integration/common"
)

// postEndSession signs bob in, posts an end session form with an id token
// hint and returns the status code and the Location relative to the test
// server, with the per-run logout id value dropped.
func postEndSession(t *testing.T, useSeeOther bool) (int, string) {
	t.Helper()
	a := require.New(t)

	pipeline := newEndSessionPipeline()

	a.NoError(pipeline.Login("bob"))
	// The switch is set after the id token is issued so that only the end
	// session redirect is under test.
	idToken := issueIdentityToken(t, pipeline, "client1")
	pipeline.Options.UseSeeOtherRedirects = useSeeOther

	values := urlpkg.Values{}
	values.Add("id_token_hint", idToken)
	values.Add("post_logout_redirect_uri", "https://client1/signout-callback")

	request, err := http.NewRequest(http.MethodPost, endSessionUrl(t, pipeline, ""), strings.NewReader(values.Encode()))
	a.NoError(err)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	pipeline.BrowserClient.AllowAutoRedirect = false
	response, err := pipeline.BrowserClient.Do(request)
	a.NoError(err)
	_ = response.Body.Close()

	location := strings.TrimPrefix(resolveLocation(t, pipeline, response.Header.Get("Location")), pipeline.TestServer.URL)
	parsed, err := urlpkg.Parse(location)
	a.NoError(err)
	query := parsed.Query()
	a.NotEmpty(query.Get(pipeline.Options.UserInteraction.LogoutIdParameter), "location=%s", location)
	query.Set(pipeline.Options.UserInteraction.LogoutIdParameter, "<id>")
	parsed.RawQuery = query.Encode()

	return response.StatusCode, parsed.String()
}

// TestSignoutPostSeeOtherRedirect proves that a POST to the end session
// endpoint answers 302 by default and 303 once UseSeeOtherRedirects is set,
// with the same logout page Location either way.
func TestSignoutPostSeeOtherRedirect(t *testing.T) {
	a := require.New(t)

	offCode, offLocation := postEndSession(t, false)
	onCode, onLocation := postEndSession(t, true)

	a.Equal(http.StatusFound, offCode)
	a.Equal(http.StatusSeeOther, onCode)
	a.True(strings.HasPrefix(onLocation, integration_common.LogoutPage+"?"), "location=%s", onLocation)
	a.Equal(offLocation, onLocation)
}
