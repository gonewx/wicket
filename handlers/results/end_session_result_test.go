// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package results

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/models/messages"
	services_impl "github.com/gonewx/wicket/services/impl"
	storagemock "github.com/gonewx/wicket/storage/mock"
	storage_models "github.com/gonewx/wicket/storage/models"
	test_common "github.com/gonewx/wicket/test/common"
	validators_models "github.com/gonewx/wicket/validators/models"
	"github.com/stretchr/testify/require"
)

type endSessionResultTests struct {
	subject                *EndSessionResult
	result                 *validators_models.EndSessionValidationResult
	options                *config_options.WicketOptions
	mockLogoutMessageStore *storagemock.MockMessageStore[messages.LogoutMessage]
	urls                   *services_impl.ServerUrls
	httpRequest            *http.Request
	mockWriter             *test_common.MockHttpWriter
}

func newEndSessionResultTests() *endSessionResultTests {
	httpRequest := httptest.NewRequest("", "https://server", nil)
	// httpContextAccessor := accessor.NewHttpContextAccessor()
	// httpContextAccessor.SetRequest(httpRequest)

	urls := services_impl.NewServerUrls(httpRequest)
	// urls.SetOrigin("https://server")

	options := config_options.NewWicketOptions()
	options.UserInteraction.LogoutUrl = "~/logout"
	options.UserInteraction.LogoutIdParameter = "logoutId"

	result := validators_models.NewEndSessionValidationResult()
	mockLogoutMessageStore := storagemock.NewMockMessageStore[messages.LogoutMessage]()

	subject := newEndSessionResult(
		result,
		options,
		test_common.NewStubClock(),
		urls,
		mockLogoutMessageStore,
	)

	return &endSessionResultTests{
		options:                options,
		result:                 result,
		subject:                subject,
		urls:                   urls,
		mockLogoutMessageStore: mockLogoutMessageStore,
		httpRequest:            httpRequest,
		mockWriter:             test_common.NewMockHttpWriter(),
	}
}

func TestEndSessionResultValidatedSignoutShouldPassLogoutMessage(t *testing.T) {
	a := require.New(t)

	test := newEndSessionResultTests()

	validatedRequest := validators_models.NewValidatedEndSessionRequest()
	validatedRequest.Client = storage_models.NewClient()
	validatedRequest.Client.ClientId = "client"
	validatedRequest.PostLogOutUri = "http://client/post-logout-callback"

	test.result.ValidatedRequest = validatedRequest

	_ = test.subject.Execute(test.mockWriter, test.httpRequest)

	a.Len(test.mockLogoutMessageStore.Messages, 1)
	location := test.mockWriter.Header().Get("Location")
	u, err := url.Parse(location)
	a.NoError(err)
	query := u.Query()

	a.True(strings.HasPrefix(location, "https://server/logout"))
	a.Greater(len(test.mockLogoutMessageStore.Ids), 0)
	a.Equal(test.mockLogoutMessageStore.Ids[0], query.Get("logoutId"))
}

func TestEndSessionResultUnvalidatedSignoutShouldNotPassLogoutMessage(t *testing.T) {
	a := require.New(t)

	test := newEndSessionResultTests()

	_ = test.subject.Execute(test.mockWriter, test.httpRequest)

	a.Len(test.mockLogoutMessageStore.Messages, 0)
	location := test.mockWriter.Header().Get("Location")
	u, err := url.Parse(location)
	a.NoError(err)
	query := u.Query()

	a.True(strings.HasPrefix(location, "https://server/logout"))
	a.Len(query, 0)
}

func TestEndSessionResultErrorResultShouldNotPassLogoutMessage(t *testing.T) {
	a := require.New(t)

	test := newEndSessionResultTests()

	validatedRequest := validators_models.NewValidatedEndSessionRequest()
	validatedRequest.Client = storage_models.NewClient()
	validatedRequest.Client.ClientId = "client"
	validatedRequest.PostLogOutUri = "http://client/post-logout-callback"

	test.result.Error = fmt.Errorf("error")
	test.result.ValidatedRequest = validatedRequest

	_ = test.subject.Execute(test.mockWriter, test.httpRequest)

	a.Len(test.mockLogoutMessageStore.Messages, 0)

	location := test.mockWriter.Header().Get("Location")
	u, err := url.Parse(location)
	a.NoError(err)

	query := u.Query()

	a.True(strings.HasPrefix(location, "https://server/logout"))
	a.Len(query, 0)
}
