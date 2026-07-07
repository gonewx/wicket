// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"log/slog"
	"net/http"
	"net/url"
)

// BackChannelLogoutHttpClient Models making HTTP requests for back-channel logout notification.
type BackChannelLogoutHttpClient struct {
	client *http.Client
	logger *slog.Logger
}

// NewBackChannelLogoutHttpClient Creates a new instance of BackChannelLogoutHttpClient.
func NewBackChannelLogoutHttpClient(logger *slog.Logger, client *http.Client) *BackChannelLogoutHttpClient {
	return &BackChannelLogoutHttpClient{
		client: client,
		logger: logger,
	}
}

// Post Posts the payload to the url.
func (c *BackChannelLogoutHttpClient) Post(url string, payload url.Values) error {
	response, err := c.client.PostForm(url, payload)

	if err != nil {
		c.logger.Error("Exception invoking back-channel logout for url", slog.String("err", err.Error()), slog.String("url", url))
		return err
	}

	if response.StatusCode != http.StatusOK {
		c.logger.Warn("Response from back-channel logout endpoint", slog.String("url", url), slog.Int("status", response.StatusCode))
	}

	c.logger.Error("Response from back-channel logout endpoint", slog.String("url", url), slog.Int("status", response.StatusCode))

	return nil
}
