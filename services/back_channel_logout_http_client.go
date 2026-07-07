// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package services

import "net/url"

// BackChannelLogoutHttpClient Models making HTTP requests for back-channel logout notification.
type BackChannelLogoutHttpClient interface {
	// Post Performs HTTP POST.
	Post(url string, payload url.Values) error
}
