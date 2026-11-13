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
	"github.com/stretchr/testify/require"
)

type checkSessionResultTests struct {
	options     *config_options.WicketOptions
	subject     *CheckSessionResult
	httpRequest *http.Request
	writer      *httptest.ResponseRecorder
}

func newCheckSessionResultTests() *checkSessionResultTests {

	httpRequest := httptest.NewRequest(http.MethodGet, "https://server", nil)

	options := config_options.NewWicketOptions()
	options.Authentication.CheckSessionCookieName = "foobar"

	subject := newCheckSessionResult(
		options,
	)

	instance := &checkSessionResultTests{
		options:     options,
		subject:     subject,
		httpRequest: httpRequest,
		writer:      httptest.NewRecorder(),
	}
	return instance
}

func TestCheckSessionResultshould_pass_results_in_body(t *testing.T) {
	a := require.New(t)

	test := newCheckSessionResultTests()

	_ = test.subject.Execute(test.writer, test.httpRequest)

	a.Equal(http.StatusOK, test.writer.Code)
	a.True(strings.HasPrefix(test.writer.Header().Get("Content-Type"), "text/html"))
	a.Contains(test.writer.Header().Get("Content-Security-Policy"), "default-src 'none';")
	a.Contains(test.writer.Header().Get("Content-Security-Policy"), "script-src 'sha256-fa5rxHhZ799izGRP38+h4ud5QXNT0SFaFlh4eqDumBI='")
	a.Contains(test.writer.Header().Get("X-Content-Security-Policy"), "default-src 'none';")
	a.Contains(test.writer.Header().Get("X-Content-Security-Policy"), "script-src 'sha256-fa5rxHhZ799izGRP38+h4ud5QXNT0SFaFlh4eqDumBI='")

	html := string(test.writer.Body.Bytes())
	a.Contains(html, "<script id='cookie-name' type='application/json'>foobar</script>")
}

func TestCheckSessionResultform_post_mode_should_add_unsafe_inline_for_csp_level_1(t *testing.T) {
	a := require.New(t)

	test := newCheckSessionResultTests()

	test.options.Csp.Level = wicket.CspLevelOne

	_ = test.subject.Execute(test.writer, test.httpRequest)

	a.Contains(test.writer.Header().Get("Content-Security-Policy"), "script-src 'unsafe-inline' 'sha256-fa5rxHhZ799izGRP38+h4ud5QXNT0SFaFlh4eqDumBI='")
	a.Contains(test.writer.Header().Get("X-Content-Security-Policy"), "script-src 'unsafe-inline' 'sha256-fa5rxHhZ799izGRP38+h4ud5QXNT0SFaFlh4eqDumBI='")
}

func TestCheckSessionResultform_post_mode_should_not_add_deprecated_header_when_it_is_disabled(t *testing.T) {
	a := require.New(t)

	test := newCheckSessionResultTests()

	test.options.Csp.AddDeprecatedHeader = false

	_ = test.subject.Execute(test.writer, test.httpRequest)

	a.Contains(test.writer.Header().Get("Content-Security-Policy"), "script-src 'sha256-fa5rxHhZ799izGRP38+h4ud5QXNT0SFaFlh4eqDumBI='")
	a.Empty(test.writer.Header().Get("X-Content-Security-Policy"))
}

func TestCheckSessionResultcan_change_cached_cookiename(t *testing.T) {
	a := require.New(t)

	for _, cookeName := range []string{"foobar", "morefoobar"} {
		t.Run(cookeName, func(t *testing.T) {
			test := newCheckSessionResultTests()

			test.options.Authentication.CheckSessionCookieName = cookeName

			_ = test.subject.Execute(test.writer, test.httpRequest)

			html := string(test.writer.Body.Bytes())
			a.Contains(html, fmt.Sprintf("<script id='cookie-name' type='application/json'>%s</script>", cookeName))
		})
	}
}
