// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

import "strings"

type InteractionResponse struct {
	IsLogin          bool
	IsConsent        bool
	RedirectUrl      string
	Error            error
	ErrorDescription string
}

func NewInteractionResponse() *InteractionResponse {
	return &InteractionResponse{}
}

func (r *InteractionResponse) IsError() bool {
	return r.Error != nil
}

func (r *InteractionResponse) IsRedirect() bool {
	return strings.TrimSpace(r.RedirectUrl) != ""
}
