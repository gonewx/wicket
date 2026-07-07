// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package extensions

import (
	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/services"
)

func SetSignOutCalled(user services.UserSession) {
	user.SetItem(gois.EnvironmentKeysWicketSignOutCalled, "true")
}

func GetSignOutCalled(user services.UserSession) bool {
	item, ok := user.Item(gois.EnvironmentKeysWicketSignOutCalled)
	if !ok {
		return false
	}

	v, ok := item.(string)
	if !ok {
		return false
	}

	return v == "true"
}
