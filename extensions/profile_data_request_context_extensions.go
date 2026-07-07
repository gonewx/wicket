// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package extensions

import (
	"log/slog"
	"strings"

	models_contexts "github.com/gonewx/wicket/models/contexts"
)

// LogProfileRequest Logs the profile request
func LogProfileRequest(c *models_contexts.ProfileDataRequestContext, logger *slog.Logger) {
	logger.Debug("Get profile called for subject {subject} from client {client} with claim types {claimTypes} via {caller}",
		slog.String("subject", GetSubjectIdFromPrincipal(c.Subject)),
		slog.String("clientName", c.Client.ClientName),
		slog.String("clientId", c.Client.ClientId),
		slog.String("claimTypes", strings.Join(c.RequestedClaimTypes, " ")),
		slog.String("caller", c.Caller))
}
