// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package messages

type ErrorMessage struct {
	DisplayMode      string
	UiLocales        string
	Error            string
	ErrorDescription string
	RequestId        string
	RedirectUri      string
	ResponseMode     string
	ClientId         string
}

func NewErrorMessage() *ErrorMessage {
	return &ErrorMessage{}
}
