// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package thirdpartylogin

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	storage_models "github.com/gonewx/wicket/storage/models"
)

func registeredClient(uri string) *storage_models.Client {
	client := storage_models.NewClient()
	client.ClientId = "rp"
	client.InitiateLoginUri = uri
	return client
}

func TestBuildInitiationUrl(t *testing.T) {
	t.Parallel()
	const issuer = "https://op.example"
	cases := map[string]struct {
		uri    string
		params Parameters
		want   url.Values
		base   string
	}{
		"all parameters": {
			uri:    "https://rp.example/login?tenant=a",
			params: Parameters{LoginHint: "alice", TargetLinkUri: "https://rp.example/app"},
			want: url.Values{
				"tenant":          {"a"},
				"iss":             {issuer},
				"login_hint":      {"alice"},
				"target_link_uri": {"https://rp.example/app"},
			},
			base: "https://rp.example/login",
		},
		"http target": {
			uri:    "https://rp.example/login",
			params: Parameters{TargetLinkUri: "http://rp.example/app"},
			want:   url.Values{"iss": {issuer}, "target_link_uri": {"http://rp.example/app"}},
			base:   "https://rp.example/login",
		},
		"upper-case scheme target": {
			uri:    "https://rp.example/login",
			params: Parameters{TargetLinkUri: "HTTPS://rp.example/app"},
			want:   url.Values{"iss": {issuer}, "target_link_uri": {"HTTPS://rp.example/app"}},
			base:   "https://rp.example/login",
		},
		"optional parameters empty": {
			uri:  "https://rp.example/login?tenant=a",
			want: url.Values{"tenant": {"a"}, "iss": {issuer}},
			base: "https://rp.example/login",
		},
		"no registered query": {
			uri:  "https://rp.example/login",
			want: url.Values{"iss": {issuer}},
			base: "https://rp.example/login",
		},
		"registered iss replaced": {
			uri:  "https://rp.example/login?iss=x&iss=y",
			want: url.Values{"iss": {issuer}},
			base: "https://rp.example/login",
		},
		"registered optional parameters dropped when empty": {
			uri:  "https://rp.example/login?login_hint=bob&target_link_uri=https%3A%2F%2Fevil.example&keep=1",
			want: url.Values{"iss": {issuer}, "keep": {"1"}},
			base: "https://rp.example/login",
		},
		"registered optional parameters replaced": {
			uri:    "https://rp.example/login?login_hint=bob",
			params: Parameters{LoginHint: "alice@example.com"},
			want:   url.Values{"iss": {issuer}, "login_hint": {"alice@example.com"}},
			base:   "https://rp.example/login",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			raw, err := BuildInitiationUrl(registeredClient(tc.uri), issuer, tc.params)
			if err != nil {
				t.Fatalf("BuildInitiationUrl: %v", err)
			}
			parsed, err := url.Parse(raw)
			if err != nil {
				t.Fatalf("parse %q: %v", raw, err)
			}
			query, err := url.ParseQuery(parsed.RawQuery)
			if err != nil {
				t.Fatalf("parse query %q: %v", parsed.RawQuery, err)
			}
			if got := parsed.Scheme + "://" + parsed.Host + parsed.Path; got != tc.base {
				t.Fatalf("base = %q, want %q", got, tc.base)
			}
			if len(query) != len(tc.want) {
				t.Fatalf("query = %v, want %v", query, tc.want)
			}
			for key, values := range tc.want {
				got := query[key]
				if len(got) != len(values) || got[0] != values[0] {
					t.Fatalf("query[%q] = %v, want %v (query %v)", key, got, values, query)
				}
			}
		})
	}
}

func TestBuildInitiationUrlEncodesInSortedOrder(t *testing.T) {
	t.Parallel()
	got, err := BuildInitiationUrl(registeredClient("https://rp.example/login?tenant=a"), "https://op.example", Parameters{LoginHint: "alice"})
	if err != nil {
		t.Fatalf("BuildInitiationUrl: %v", err)
	}
	const want = "https://rp.example/login?iss=https%3A%2F%2Fop.example&login_hint=alice&tenant=a"
	if got != want {
		t.Fatalf("url = %q, want %q", got, want)
	}
}

func TestBuildInitiationUrlRejects(t *testing.T) {
	t.Parallel()
	const hint = "alice@example.com"
	cases := map[string]struct {
		client *storage_models.Client
		issuer string
		target string
		want   error
	}{
		"nil client":            {client: nil, issuer: "https://op.example", want: ErrNotRegistered},
		"not registered":        {client: registeredClient(""), issuer: "https://op.example", want: ErrNotRegistered},
		"http registration":     {client: registeredClient("http://rp.example/login"), issuer: "https://op.example", want: ErrInvalidInitiateLoginUri},
		"relative registration": {client: registeredClient("/login"), issuer: "https://op.example", want: ErrInvalidInitiateLoginUri},
		"unparsable query":      {client: registeredClient("https://rp.example/login?a=%zz"), issuer: "https://op.example", want: ErrInvalidInitiateLoginUri},
		"http issuer":           {client: registeredClient("https://rp.example/login"), issuer: "http://op.example", want: ErrInvalidIssuer},
		"empty issuer":          {client: registeredClient("https://rp.example/login"), issuer: "", want: ErrInvalidIssuer},
		"issuer without host":   {client: registeredClient("https://rp.example/login"), issuer: "https://", want: ErrInvalidIssuer},
		"relative target":       {client: registeredClient("https://rp.example/login"), issuer: "https://op.example", target: "/app", want: ErrInvalidTargetLinkUri},
		"target without host":   {client: registeredClient("https://rp.example/login"), issuer: "https://op.example", target: "https:///app", want: ErrInvalidTargetLinkUri},
		"target with port only": {client: registeredClient("https://rp.example/login"), issuer: "https://op.example", target: "https://:443/app", want: ErrInvalidTargetLinkUri},
		"javascript target":     {client: registeredClient("https://rp.example/login"), issuer: "https://op.example", target: "javascript://x/%0Aalert(1)", want: ErrInvalidTargetLinkUri},
		"custom scheme target":  {client: registeredClient("https://rp.example/login"), issuer: "https://op.example", target: "custom://rp.example/app", want: ErrInvalidTargetLinkUri},
		"target without scheme": {client: registeredClient("https://rp.example/login"), issuer: "https://op.example", target: "rp.example/app", want: ErrInvalidTargetLinkUri},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := BuildInitiationUrl(tc.client, tc.issuer, Parameters{LoginHint: hint, TargetLinkUri: tc.target})
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if got != "" {
				t.Fatalf("url = %q, want empty", got)
			}
			if strings.Contains(err.Error(), hint) {
				t.Fatalf("error text %q carries the login hint", err.Error())
			}
		})
	}
}

func TestInitiateWithoutRequestScope(t *testing.T) {
	t.Parallel()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "https://host.example/start", nil)
	err := Initiate(recorder, request, "rp", Parameters{LoginHint: "alice"})
	if !errors.Is(err, ErrNoRequestScope) {
		t.Fatalf("err = %v, want %v", err, ErrNoRequestScope)
	}
	if len(recorder.Header()) != 0 || recorder.Body.Len() != 0 {
		t.Fatalf("response written: header %v body %q", recorder.Header(), recorder.Body.String())
	}
	if err := Initiate(recorder, nil, "rp", Parameters{}); !errors.Is(err, ErrNoRequestScope) {
		t.Fatalf("nil request err = %v, want %v", err, ErrNoRequestScope)
	}
}
