// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package common

import (
	"fmt"
	"math"
	"net/http"
	"net/http/cookiejar"
	"net/url"

	"github.com/gonewx/wicket/utils"
)

// combine: test/IdentityServer.IntegrationTests/Common/BrowserHandler.cs test/IdentityServer.IntegrationTests/Common/BrowserClient.cs

type BrowserClient struct {
	*http.Client

	cookies            map[string][]*http.Cookie
	AllowCookies       bool
	AllowAutoRedirect  bool
	ErrorRedirectLimit int

	StopRedirectingAfter int
}

func NewBrowserClient(client *http.Client) *BrowserClient {
	bc := &BrowserClient{
		cookies: make(map[string][]*http.Cookie),

		Client:               client,
		AllowCookies:         true,
		AllowAutoRedirect:    true,
		ErrorRedirectLimit:   20,
		StopRedirectingAfter: math.MaxInt32,
	}

	bc.Client.CheckRedirect = bc.checkRedirect

	if !bc.AllowCookies {
		bc.Jar = nil
	} else {
		var err error
		bc.Jar, err = cookiejar.New(nil)
		if err != nil {
			panic(err)
		}
	}

	return bc
}

func (c *BrowserClient) SetTransport(transport http.RoundTripper) {
	c.Client.Transport = transport
}

// func (c *BrowserClient) Get(url string) (*http.Response, error) {
// 	req, err := http.NewRequest(http.MethodGet, url, nil)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return c.Send(context.Background(), req)
// }

// func (c *BrowserClient) Post(url, contentType string, body io.Reader) (*http.Response, error) {
// 	req, err := http.NewRequest(http.MethodPost, url, body)
// 	if err != nil {
// 		return nil, err
// 	}

// 	req.Header.Set("Content-Type", contentType)

// 	return c.Send(context.Background(), req)
// }

// func (c *BrowserClient) PostForm(url string, data url.Values) (*http.Response, error) {
// 	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(data.Encode()))
// 	if err != nil {
// 		return nil, err
// 	}

// 	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

// 	return c.Send(context.Background(), req)
// }

func (c *BrowserClient) checkRedirect(req *http.Request, via []*http.Request) error {
	redirectCount := len(via) - 1

	if !c.AllowAutoRedirect || redirectCount >= c.StopRedirectingAfter {
		return http.ErrUseLastResponse
	}

	// check redirect count login is different from the original code
	// 应该多1
	if redirectCount >= c.ErrorRedirectLimit {
		return fmt.Errorf("Too many redirects")
	}

	return nil
}

// func (c *BrowserClient) Send(ctx context.Context, req *http.Request) (*http.Response, error) {
// 	response, err := c.SendCookies(ctx, req)
// 	if err != nil {
// 		return nil, err
// 	}

// 	redirectCount := 0

// 	for c.AllowAutoRedirect &&
// 		response.StatusCode >= 300 && response.StatusCode < 400 &&
// 		redirectCount < c.StopRedirectingAfter {
// 		if redirectCount >= c.ErrorRedirectLimit {
// 			return nil, fmt.Errorf("%w Too many redirects. Error limit = %d ", gois.InvalidOperationException, redirectCount)
// 		}

// 		locationString := response.Header.Get("Location")
// 		location, err := url.Parse(locationString)
// 		if err != nil {
// 			return nil, fmt.Errorf("%w location parse:  %v ", gois.InvalidOperationException, err)
// 		}

// 		request := httptest.NewRequest(http.MethodGet, req.URL.ResolveReference(location).String(), nil)

// 		response, err = c.SendCookies(ctx, request)
// 		if err != nil {
// 			return nil, fmt.Errorf("%w SendCookies:  %v ", gois.InvalidOperationException, err)
// 		}

// 		redirectCount++
// 	}

// 	return response, nil
// }

// func (c *BrowserClient) SendCookies(ctx context.Context, req *http.Request) (*http.Response, error) {
// 	if c.AllowCookies {
// 		cookies := utils.Select(
// 			c.cookies[req.URL.Host],
// 			func(c *http.Cookie) string { return c.String() })

// 		cookieHeader := strings.Join(cookies, "; ")
// 		if cookieHeader != "" {
// 			req.Header.Set("Cookie", cookieHeader)
// 		}
// 	}

// 	response, err := c.Client.Do(req)
// 	if err != nil {
// 		return nil, err
// 	}

// 	if c.AllowCookies {
// 		c.cookies[req.URL.Host] = response.Cookies()
// 	}

// 	return response, err
// }

func (c *BrowserClient) GetCookie(uri string, name string) *http.Cookie {
	u, _ := url.Parse(uri)
	cookies := c.Jar.Cookies(u)
	return utils.FirstOrDefault(utils.Where(cookies, func(c *http.Cookie) bool { return c.Name == name }))
}

func (c *BrowserClient) RemoveCookie(uri string, name string) {
	u, _ := url.Parse(uri)
	cookies := c.Jar.Cookies(u)
	cookie := utils.FirstOrDefault(utils.Where(cookies, func(c *http.Cookie) bool { return c.Name == name }))
	if cookie != nil {
		cookie.MaxAge = -1
		c.Jar.SetCookies(u, cookies)
	}
}
