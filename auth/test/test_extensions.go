// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package test

import (
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"

	"github.com/gonewx/wicket/auth"
	claimspkg "github.com/gonewx/wicket/claims"
	"github.com/tidwall/gjson"
)

const (
	CookieAuthenticationScheme = "External"
)

func Send(server *httptest.Server, uri string) (*transaction, error) {
	return SendWithCookieHeader(server, uri, "")
}

func SendWithCookieHeader(server *httptest.Server, uri string, cookieHeader string) (*transaction, error) {
	req, err := http.NewRequest(http.MethodGet, server.URL+uri, nil)
	if err != nil {
		return nil, err
	}

	if cookieHeader != "" {
		req.Header.Set("Cookie", cookieHeader)
	}

	client := server.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	trans := &transaction{
		Request:  req,
		Response: response,
	}

	trans.SetCookie = response.Header["Set-Cookie"]

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	trans.ResponseText = string(body)

	if response.Header.Get("Content-Type") != "" {
		mediaType, _, _ := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if mediaType == "application/json" {
			trans.ResponseElement = gjson.Parse(string(body))
		}

	}
	return trans, nil
}

func DescribeWithPrincipal(res http.ResponseWriter, principal *claimspkg.ClaimsPrincipal) {
	res.Header().Add("Content-Type", "application/json")
	res.WriteHeader(http.StatusOK)

	r, err := json.Marshal(principal)
	// xml, err := xml.Marshal(&result)
	if err != nil {
		panic(err)
	}
	_, _ = res.Write(r)
}

func DescribeWithTokens(res http.ResponseWriter, tokens []*auth.Token) {
	res.Header().Add("Content-Type", "application/json")
	res.WriteHeader(http.StatusOK)

	r, err := json.Marshal(tokens)
	// xml, err := xml.Marshal(&result)
	if err != nil {
		panic(err)
	}
	_, _ = res.Write(r)
}
