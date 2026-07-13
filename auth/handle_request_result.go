// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package auth

type HandleRequestResult struct {
	*Result

	// Indicates that stage of authentication was directly handled by
	// user intervention and no further processing should be attempted.
	Handled bool

	// Indicates that the default authentication logic should be
	// skipped and that the rest of the pipeline should be invoked.
	Skipped bool
}

func NewHandleRequestResult() *HandleRequestResult {
	return &HandleRequestResult{
		Result: NewResult(),
	}
}

// Indicates that authentication was successful.
func HandleRequestSuccess(ticket *Ticket) *HandleRequestResult {
	r := NewHandleRequestResult()
	r.Ticket = ticket
	r.Properties = ticket.Properties

	return r
}

// Indicates that there was a failure during authentication.
func HandleRequestFail(failure error, properties *Properties) *HandleRequestResult {
	r := NewHandleRequestResult()
	r.Failure = failure
	r.Properties = properties

	return r
}

// Discontinue all processing for this request and return to the client.
func Handle() *HandleRequestResult {
	r := NewHandleRequestResult()
	r.Handled = true

	return r
}

// Discontinue processing the request in the current handler.
func SkipHandler() *HandleRequestResult {
	r := NewHandleRequestResult()
	r.Skipped = true

	return r
}

// / Discontinue processing the request in the current handler.
func HandleRequestSkipResult() *HandleRequestResult {
	r := NewHandleRequestResult()
	r.Skipped = true

	return r
}

// Indicates that there were no results produced during authentication.
func HandleRequestNoResult() *HandleRequestResult {
	r := NewHandleRequestResult()
	r.None = true

	return r
}
