// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package results

import (
	"encoding/json"
	"net/http"
)

// DeviceAuthorizationErrorResult answers a rejected device authorization
// request with an RFC 6749 §5.2 error: 400, a JSON body holding only the
// error code, and no-cache headers, all headers set before the status code.
type DeviceAuthorizationErrorResult struct {
	Error error
}

func NewDeviceAuthorizationErrorResult(err error) *DeviceAuthorizationErrorResult {
	return &DeviceAuthorizationErrorResult{Error: err}
}

func (r *DeviceAuthorizationErrorResult) Execute(w http.ResponseWriter, _ *http.Request) error {
	HttpRespSetNoCache(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)

	return json.NewEncoder(w).Encode(map[string]string{"error": r.Error.Error()})
}
