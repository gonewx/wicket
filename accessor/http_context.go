// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package accessor

import "net/http"

// HttpContextAccessor exposes the current HTTP request for request-scoped consumers.
// input: request -> behavior: store/read request in scope -> output: request or nil.
type HttpContextAccessor interface {
	Request() *http.Request
	SetRequest(*http.Request)
}

// HttpResponseWriterAccessor exposes the current response writer for request-scoped consumers.
// input: response writer -> behavior: store/read writer in scope -> output: writer or nil.
type HttpResponseWriterAccessor interface {
	ResponseWriter() http.ResponseWriter
	SetResponseWriter(http.ResponseWriter)
}

type DefaultHttpContextAccessor struct {
	request  *http.Request
	response http.ResponseWriter
}

func NewDefaultHttpContextAccessor() *DefaultHttpContextAccessor {
	return &DefaultHttpContextAccessor{}
}

func (a *DefaultHttpContextAccessor) Request() *http.Request {
	return a.request
}

func (a *DefaultHttpContextAccessor) SetRequest(request *http.Request) {
	a.request = request
}

func (a *DefaultHttpContextAccessor) ResponseWriter() http.ResponseWriter {
	return a.response
}

func (a *DefaultHttpContextAccessor) SetResponseWriter(response http.ResponseWriter) {
	a.response = response
}
