// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package results

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gonewx/wicket"
	config_options "github.com/gonewx/wicket/config/options"
	test_common "github.com/gonewx/wicket/test/common"
	"github.com/stretchr/testify/require"
)

type checkSessionResultTests struct {
	options     *config_options.IdentityServerOptions
	subject     *CheckSessionResult
	httpRequest *http.Request
	mockWriter  *test_common.MockHttpWriter
}

func newCheckSessionResultTests() *checkSessionResultTests {

	httpRequest := httptest.NewRequest(http.MethodGet, "https://server", nil)

	options := config_options.NewIdentityServerOptions()
	options.Authentication.CheckSessionCookieName = "foobar"

	subject := newCheckSessionResult(
		options,
	)

	instance := &checkSessionResultTests{
		options:     options,
		subject:     subject,
		httpRequest: httpRequest,
		mockWriter:  test_common.NewMockHttpWriter(),
	}
	return instance
}

// test/IdentityServer.UnitTests/Endpoints/Results/CheckSessionResultTests.cs
func TestCheckSessionResultshould_pass_results_in_body(t *testing.T) {
	a := require.New(t)

	test := newCheckSessionResultTests()

	_ = test.subject.Execute(test.mockWriter, test.httpRequest)

	a.Equal(http.StatusText(http.StatusOK), test.mockWriter.Header().Get("Code"))
	a.True(strings.HasPrefix(test.mockWriter.Header().Get("Content-Type"), "text/html"))
	a.Contains(test.mockWriter.Header().Get("Content-Security-Policy"), "default-src 'none';")
	a.Contains(test.mockWriter.Header().Get("Content-Security-Policy"), "script-src 'sha256-fa5rxHhZ799izGRP38+h4ud5QXNT0SFaFlh4eqDumBI='")
	a.Contains(test.mockWriter.Header().Get("X-Content-Security-Policy"), "default-src 'none';")
	a.Contains(test.mockWriter.Header().Get("X-Content-Security-Policy"), "script-src 'sha256-fa5rxHhZ799izGRP38+h4ud5QXNT0SFaFlh4eqDumBI='")

	html := string(test.mockWriter.Data)
	a.Contains(html, "<script id='cookie-name' type='application/json'>foobar</script>")
}

func TestCheckSessionResultform_post_mode_should_add_unsafe_inline_for_csp_level_1(t *testing.T) {
	a := require.New(t)

	test := newCheckSessionResultTests()

	test.options.Csp.Level = gois.CspLevelOne

	_ = test.subject.Execute(test.mockWriter, test.httpRequest)

	a.Contains(test.mockWriter.Header().Get("Content-Security-Policy"), "script-src 'unsafe-inline' 'sha256-fa5rxHhZ799izGRP38+h4ud5QXNT0SFaFlh4eqDumBI='")
	a.Contains(test.mockWriter.Header().Get("X-Content-Security-Policy"), "script-src 'unsafe-inline' 'sha256-fa5rxHhZ799izGRP38+h4ud5QXNT0SFaFlh4eqDumBI='")
}

func TestCheckSessionResultform_post_mode_should_not_add_deprecated_header_when_it_is_disabled(t *testing.T) {
	a := require.New(t)

	test := newCheckSessionResultTests()

	test.options.Csp.AddDeprecatedHeader = false

	_ = test.subject.Execute(test.mockWriter, test.httpRequest)

	a.Contains(test.mockWriter.Header().Get("Content-Security-Policy"), "script-src 'sha256-fa5rxHhZ799izGRP38+h4ud5QXNT0SFaFlh4eqDumBI='")
	a.Empty(test.mockWriter.Header().Get("X-Content-Security-Policy"))
}

func TestCheckSessionResultcan_change_cached_cookiename(t *testing.T) {
	a := require.New(t)

	for _, cookeName := range []string{"foobar", "morefoobar"} {
		t.Run(cookeName, func(t *testing.T) {
			test := newCheckSessionResultTests()

			test.options.Authentication.CheckSessionCookieName = cookeName

			_ = test.subject.Execute(test.mockWriter, test.httpRequest)

			html := string(test.mockWriter.Data)
			a.Contains(html, fmt.Sprintf("<script id='cookie-name' type='application/json'>%s</script>", cookeName))
		})
	}
}
