// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package common

import (
	"net/url"

	"github.com/gonewx/wicket/models/messages"
)

// From: IdentityServer4/src/IdentityServer/Stores/Default/QueryStringAuthorizationParametersMessageStore.cs
type QueryStringAuthorizationParametersMessageStore struct{}

func NewQueryStringAuthorizationParametersMessageStore() *QueryStringAuthorizationParametersMessageStore {
	return &QueryStringAuthorizationParametersMessageStore{}
}

func (s *QueryStringAuthorizationParametersMessageStore) Write(message *messages.Message[url.Values]) (string, error) {
	queryString := message.Data.Encode()
	return queryString, nil
}

func (s *QueryStringAuthorizationParametersMessageStore) Read(id string) (*messages.Message[url.Values], error) {
	parsedUrl, err := url.ParseQuery(id)
	if err != nil {
		return nil, err
	}

	msg := messages.NewMessage(parsedUrl)

	return msg, nil
}

func (s *QueryStringAuthorizationParametersMessageStore) Delete(id string) error {
	return nil
}
