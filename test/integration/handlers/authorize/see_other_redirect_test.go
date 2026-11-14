// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package authorize

import (
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/gonewx/wicket"
	integration_common "github.com/gonewx/wicket/test/integration/common"
)

// seeOtherRequest describes one authorize request and the redirect target it
// must produce.
type seeOtherRequest struct {
	method     string
	login      bool
	request    *integration_common.AuthorizeUrl
	wantPrefix func(p *integration_common.WicketPipeline) string
}

func validAuthorizeRequest() *integration_common.AuthorizeUrl {
	return &integration_common.AuthorizeUrl{
		ClientId:     knownClientId,
		ResponseType: wicket.ResponseTypesIdToken,
		Scope:        wicket.StandardScopesOpenId,
		RedirectUri:  knownRedirectUri,
		State:        "some-state",
		Nonce:        "some-nonce",
	}
}

// sendAuthorize issues the authorize request without following redirects and
// returns the status code and Location.
func sendAuthorize(t *testing.T, useSeeOther bool, tc seeOtherRequest) (*integration_common.WicketPipeline, int, string) {
	t.Helper()
	a := require.New(t)

	p := newAuthorizePipeline(t)
	p.Options.UseSeeOtherRedirects = useSeeOther
	if tc.login {
		a.NoError(p.Login("endpoint-subject"))
	}

	u, err := p.CreateAuthorizeUrl(tc.request)
	a.NoError(err)

	p.BrowserClient.AllowAutoRedirect = false
	var resp *http.Response
	if tc.method == http.MethodPost {
		form := u.Query()
		u.RawQuery = ""
		resp, err = p.BrowserClient.Post(u.String(), "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	} else {
		resp, err = p.BrowserClient.Get(u.String())
	}
	a.NoError(err)
	_ = resp.Body.Close()

	location := resp.Header.Get("Location")
	if strings.HasPrefix(location, "/") {
		location = p.TestServer.URL + location
	}
	return p, resp.StatusCode, location
}

// locationShape reduces a location to its target and the sorted names of its
// query and fragment parameters, dropping per-run values. The test server port
// differs per pipeline, so the host of a server-local target is dropped too.
func locationShape(t *testing.T, p *integration_common.WicketPipeline, location string) string {
	t.Helper()
	location = strings.TrimPrefix(location, p.TestServer.URL)
	u, err := url.Parse(location)
	require.NoError(t, err)

	names := func(raw string) string {
		values, err := url.ParseQuery(raw)
		require.NoError(t, err)
		keys := make([]string, 0, len(values))
		for k := range values {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return strings.Join(keys, ",")
	}

	target := u.Scheme + "://" + u.Host + u.Path
	return target + "?" + names(u.RawQuery) + "#" + names(u.Fragment)
}

// TestAuthorizeSeeOtherRedirects drives authorize requests through the
// pipeline with UseSeeOtherRedirects off and on: off keeps 302, on answers
// 303, and the Location is the same either way.
func TestAuthorizeSeeOtherRedirects(t *testing.T) {
	t.Parallel()

	loginPrefix := func(p *integration_common.WicketPipeline) string {
		return p.TestServer.URL + integration_common.LoginPage
	}
	errorPrefix := func(p *integration_common.WicketPipeline) string {
		return p.TestServer.URL + integration_common.ErrorPage
	}
	clientPrefix := func(*integration_common.WicketPipeline) string {
		return knownRedirectUri + "#"
	}

	unknownClient := validAuthorizeRequest()
	unknownClient.ClientId = "ghost-client"

	cases := map[string]seeOtherRequest{
		"POST anonymous goes to the login page": {
			method:     http.MethodPost,
			request:    validAuthorizeRequest(),
			wantPrefix: loginPrefix,
		},
		"POST signed in goes to the client": {
			method:     http.MethodPost,
			login:      true,
			request:    validAuthorizeRequest(),
			wantPrefix: clientPrefix,
		},
		"POST unknown client goes to the error page": {
			method:     http.MethodPost,
			request:    unknownClient,
			wantPrefix: errorPrefix,
		},
		"GET anonymous goes to the login page": {
			method:     http.MethodGet,
			request:    validAuthorizeRequest(),
			wantPrefix: loginPrefix,
		},
		"GET signed in goes to the client": {
			method:     http.MethodGet,
			login:      true,
			request:    validAuthorizeRequest(),
			wantPrefix: clientPrefix,
		},
	}

	for name, tc := range cases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			a := require.New(t)

			offPipeline, offCode, offLocation := sendAuthorize(t, false, tc)
			onPipeline, onCode, onLocation := sendAuthorize(t, true, tc)

			a.Equal(http.StatusFound, offCode, "location=%s", offLocation)
			a.Equal(http.StatusSeeOther, onCode, "location=%s", onLocation)

			a.Truef(strings.HasPrefix(offLocation, tc.wantPrefix(offPipeline)), "off location=%s", offLocation)
			a.Truef(strings.HasPrefix(onLocation, tc.wantPrefix(onPipeline)), "on location=%s", onLocation)
			a.Equal(locationShape(t, offPipeline, offLocation), locationShape(t, onPipeline, onLocation))
		})
	}
}

// TestAuthorizeSeeOtherRedirectsKeepLocation proves, on a single pipeline, that
// the switch changes only the status code of the login page redirect: the
// Location is byte-identical.
func TestAuthorizeSeeOtherRedirectsKeepLocation(t *testing.T) {
	t.Parallel()
	a := require.New(t)

	p := newAuthorizePipeline(t)
	u, err := p.CreateAuthorizeUrl(validAuthorizeRequest())
	a.NoError(err)
	form := u.Query()
	u.RawQuery = ""

	post := func() (int, string) {
		p.BrowserClient.AllowAutoRedirect = false
		resp, err := p.BrowserClient.Post(u.String(), "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
		a.NoError(err)
		_ = resp.Body.Close()
		return resp.StatusCode, resp.Header.Get("Location")
	}

	p.Options.UseSeeOtherRedirects = false
	offCode, offLocation := post()
	p.Options.UseSeeOtherRedirects = true
	onCode, onLocation := post()

	a.Equal(http.StatusFound, offCode)
	a.Equal(http.StatusSeeOther, onCode)
	a.NotEmpty(onLocation)
	a.Equal(offLocation, onLocation)
}
