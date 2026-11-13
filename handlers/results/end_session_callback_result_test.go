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
	validators_models "github.com/gonewx/wicket/validators/models"
	"github.com/stretchr/testify/require"
)

type endSessionCallbackResultTests struct {
	validationResult *validators_models.EndSessionCallbackValidationResult
	options          *config_options.WicketOptions
	subject          *EndSessionCallbackResult
	writer           *httptest.ResponseRecorder
}

func newEndSessionCallbackResultTests() *endSessionCallbackResultTests {
	validationResult := validators_models.NewEndSessionCallbackValidationResult()
	options := config_options.NewWicketOptions()

	subject := newEndSessionCallbackResult(
		validationResult,
		options,
	)
	subject.Result = validationResult

	return &endSessionCallbackResultTests{
		options:          options,
		validationResult: validationResult,
		subject:          subject,
		writer:           httptest.NewRecorder(),
	}
}

func TestEndSessionCallbackResultDefaultOptionsShouldEmitFrameSrcCspHeaders(t *testing.T) {
	a := require.New(t)

	test := newEndSessionCallbackResultTests()
	test.validationResult.FrontChannelLogoutUrls = []string{"http://foo"}

	request := httptest.NewRequest(http.MethodGet, "/", nil)

	_ = test.subject.Execute(test.writer, request)

	header := test.writer.Header()["Content-Security-Policy"]
	a.Greater(len(header), 0)
	a.Contains(header[0], "frame-src http://foo")
}

func TestEndSessionCallbackResultRelaxCspOptionsShouldPreventFrameSrcCspHeaders(t *testing.T) {
	a := require.New(t)

	test := newEndSessionCallbackResultTests()
	test.options.Authentication.RequireCspFrameSrcForSignout = false
	test.validationResult.FrontChannelLogoutUrls = []string{"http://foo"}

	request := httptest.NewRequest(http.MethodGet, "/", nil)

	_ = test.subject.Execute(test.writer, request)

	header := test.writer.Header()["Content-Security-Policy"]

	a.Nil(header)
}

func TestEndSessionCallbackResulterror_should_return_400(t *testing.T) {
	a := require.New(t)

	test := newEndSessionCallbackResultTests()
	test.validationResult.Error = fmt.Errorf("error")

	request := httptest.NewRequest(http.MethodGet, "https://server", nil)

	_ = test.subject.Execute(test.writer, request)

	a.Equal(http.StatusBadRequest, test.writer.Code)
}

func TestEndSessionCallbackResultsuccess_should_render_html_and_iframes(t *testing.T) {
	a := require.New(t)

	test := newEndSessionCallbackResultTests()
	test.validationResult.Error = nil
	test.validationResult.FrontChannelLogoutUrls = []string{"http://foo.com", "http://bar.com"}

	request := httptest.NewRequest(http.MethodGet, "https://server", nil)

	_ = test.subject.Execute(test.writer, request)

	a.True(strings.HasPrefix(test.writer.Header().Get("Content-Type"), "text/html"))
	a.Contains(strings.Join(test.writer.Header().Values("Cache-Control"), ", "), "no-store")
	a.Contains(strings.Join(test.writer.Header().Values("Cache-Control"), ", "), "no-cache")
	a.Contains(strings.Join(test.writer.Header().Values("Cache-Control"), ", "), "max-age=0")
	a.Contains(test.writer.Header().Get("Content-Security-Policy"), "default-src 'none';")
	a.Contains(test.writer.Header().Get("Content-Security-Policy"), "style-src 'sha256-e6FQZewefmod2S/5T11pTXjzE2vn3/8GRwWOs917YE4=';")
	a.Contains(test.writer.Header().Get("Content-Security-Policy"), "frame-src http://foo.com http://bar.com")
	a.Contains(test.writer.Header().Get("X-Content-Security-Policy"), "default-src 'none';")
	a.Contains(test.writer.Header().Get("X-Content-Security-Policy"), "style-src 'sha256-e6FQZewefmod2S/5T11pTXjzE2vn3/8GRwWOs917YE4=';")
	a.Contains(test.writer.Header().Get("X-Content-Security-Policy"), "frame-src http://foo.com http://bar.com")

	html := string(test.writer.Body.Bytes())
	a.Contains(html, "<iframe loading='eager' allow='' src='http://foo.com'></iframe>")
	a.Contains(html, "<iframe loading='eager' allow='' src='http://bar.com'></iframe>")
}

func TestEndSessionCallbackResultfsuccess_should_add_unsafe_inline_for_csp_level_1(t *testing.T) {
	a := require.New(t)

	test := newEndSessionCallbackResultTests()
	test.validationResult.Error = nil
	test.options.Csp.Level = wicket.CspLevelOne

	request := httptest.NewRequest(http.MethodGet, "https://server", nil)

	_ = test.subject.Execute(test.writer, request)

	a.Contains(test.writer.Header().Get("Content-Security-Policy"), "style-src 'unsafe-inline' 'sha256-e6FQZewefmod2S/5T11pTXjzE2vn3/8GRwWOs917YE4='")
	a.Contains(test.writer.Header().Get("X-Content-Security-Policy"), "style-src 'unsafe-inline' 'sha256-e6FQZewefmod2S/5T11pTXjzE2vn3/8GRwWOs917YE4='")
}

func TestEndSessionCallbackResultfform_post_mode_should_not_add_deprecated_header_when_it_is_disabled(t *testing.T) {
	a := require.New(t)

	test := newEndSessionCallbackResultTests()
	test.validationResult.Error = nil
	test.options.Csp.AddDeprecatedHeader = false

	request := httptest.NewRequest(http.MethodGet, "https://server", nil)

	_ = test.subject.Execute(test.writer, request)

	a.Contains(test.writer.Header().Get("Content-Security-Policy"), "style-src 'sha256-e6FQZewefmod2S/5T11pTXjzE2vn3/8GRwWOs917YE4='")
	a.Empty(test.writer.Header().Get("X-Content-Security-Policy"))
}
