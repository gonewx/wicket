// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package di

import (
	"github.com/gonewx/godi"
	"github.com/gonewx/wicket/services"
)

func userSessionFromProvider(p godi.Provider) services.UserSession {
	return godi.GetRequired[services.UserSession](p)
}
