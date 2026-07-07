// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package hosting

import "github.com/gonewx/godi"

type Endpoint struct {
	Name    string
	Path    string
	Handler func(p godi.Provider) (EndpointHandler, error)
}
