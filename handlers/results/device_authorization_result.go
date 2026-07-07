// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package results

import (
	"net/http"

	responses_models "github.com/gonewx/wicket/responses/models"
)

type DeviceAuthorizationResult struct {
	Response *responses_models.DeviceAuthorizationResponse
}

func NewDeviceAuthorizationResult(
	response *responses_models.DeviceAuthorizationResponse,
) *DeviceAuthorizationResult {
	return &DeviceAuthorizationResult{
		Response: response,
	}
}

func (dar *DeviceAuthorizationResult) Execute(w http.ResponseWriter, r *http.Request) error {
	HttpRespSetNoCache(w)

	dto := make(map[string]interface{})

	w.WriteHeader(http.StatusOK)
	dto["device_code"] = dar.Response.DeviceCode
	dto["user_code"] = dar.Response.UserCode
	dto["verification_uri"] = dar.Response.VerificationUri
	dto["verification_uri_complete"] = dar.Response.VerificationUriComplete
	dto["expires_in"] = dar.Response.DeviceCodeLifetime
	dto["interval"] = dar.Response.Interval

	return HttpRespWriteJson(w, dto, "")
}
