// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package di

import (
	"fmt"

	storage_models "github.com/gonewx/wicket/storage/models"
)

// requireClientInitiateLoginUris fails assembly when a client of the static
// list (SetClients or SetClientsProvider) registers an initiate_login_uri
// that is not an absolute https URI. Clients of an injected store are not
// visible at assembly; the client configuration validator rejects them on
// read instead.
func (c *ServerConfig) requireClientInitiateLoginUris() {
	for _, client := range c.Clients() {
		if client == nil || client.InitiateLoginUri == "" {
			continue
		}
		if !storage_models.IsAbsoluteHttpsUri(client.InitiateLoginUri) {
			panic(fmt.Sprintf("client %q registers an initiate_login_uri that is not an absolute https URI", client.ClientId))
		}
	}
}
