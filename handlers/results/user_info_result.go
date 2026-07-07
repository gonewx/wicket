// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package results

import (
	"net/http"
)

type UserInfoResult struct {
	Claims map[string]any
}

func NewUserInfoResult(
	claims map[string]any,
) *UserInfoResult {
	return &UserInfoResult{
		Claims: claims,
	}
}

func (uir *UserInfoResult) Execute(w http.ResponseWriter, r *http.Request) error {
	HttpRespSetNoCache(w)

	return HttpRespWriteJson(w, uir.Claims, "")
}
