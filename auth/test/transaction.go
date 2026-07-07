// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package test

import (
	"net/http"

	"github.com/tidwall/gjson"
)

type transaction struct {
	Request         *http.Request
	Response        *http.Response
	SetCookie       []string
	ResponseText    string
	ResponseElement gjson.Result
}
