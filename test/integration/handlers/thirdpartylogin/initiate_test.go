// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package thirdpartylogin

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/gonewx/godi"
	"github.com/stretchr/testify/require"

	"github.com/gonewx/wicket/extensions"
	"github.com/gonewx/wicket/hosting"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/storage"
	storage_memory "github.com/gonewx/wicket/storage/memory"
	storage_models "github.com/gonewx/wicket/storage/models"
	integration_common "github.com/gonewx/wicket/test/integration/common"
	"github.com/gonewx/wicket/thirdpartylogin"
)

const (
	issuer        = "https://op.example"
	registeredUri = "https://rp.example/login?tenant=a"
	loginHint     = "alice@example.com"
	targetLinkUri = "https://rp.example/app"

	registeredId   = "registered"
	unregisteredId = "unregistered"
	disabledId     = "disabled"
	httpId         = "http-registered"
	initiatePath   = "/start-login"
)

func initiatingClient(id, uri string, enabled bool) *storage_models.Client {
	client := storage_models.NewClient()
	client.ClientId = id
	client.Enabled = enabled
	client.InitiateLoginUri = uri
	return client
}

// clients returns the registered clients. The client registering an http
// initiate_login_uri is only part of an injected store: in the static list it
// fails assembly at Freeze.
func clients(injected bool) []*storage_models.Client {
	list := []*storage_models.Client{
		initiatingClient(registeredId, registeredUri, true),
		initiatingClient(unregisteredId, "", true),
		initiatingClient(disabledId, registeredUri, false),
	}
	if injected {
		list = append(list, initiatingClient(httpId, "http://rp.example/login", true))
	}
	return list
}

// host is a host application serving one page that initiates a client's
// login; it records what the initiation returned.
type host struct {
	pipeline *integration_common.WicketPipeline
	server   *httptest.Server

	mu         sync.Mutex
	lastErr    error
	storeError error
	issuer     string
}

// newHost wraps the host page in wicket's request scope and middleware, as a
// host serving its own pages next to wicket does. injected selects a host
// client store over the static client list; issuerUri, when not empty,
// configures the issuer.
func newHost(t *testing.T, injected bool, issuerUri string) *host {
	t.Helper()
	p := integration_common.NewWicketPipeline()
	if injected {
		store, err := storage_memory.NewMemoryClientStore(clients(true))
		require.NoError(t, err)
		p.ClientStore = store
	} else {
		p.Clients = clients(false)
	}
	p.Initialize()
	t.Cleanup(p.TestServer.Close)
	p.Options.IssuerUri = issuerUri

	h := &host{pipeline: p}
	mux := http.NewServeMux()
	mux.HandleFunc(initiatePath, func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		storeErr := h.loadThroughStore(r, query.Get("client_id"))
		err := thirdpartylogin.Initiate(w, r, query.Get("client_id"), thirdpartylogin.Parameters{
			LoginHint:     query.Get("login_hint"),
			TargetLinkUri: query.Get("target_link_uri"),
		})
		// The host decides how to answer a failed initiation; this one
		// leaves the response untouched so the test sees exactly what the
		// initiation wrote.
		h.mu.Lock()
		h.lastErr = err
		h.storeError = storeErr
		h.issuer = godi.GetRequired[services.IssuerNameService](hosting.ScopeFrom(r.Context())).GetCurrent()
		h.mu.Unlock()
	})
	h.server = httptest.NewServer(hosting.ScopeMiddleware(p.Root)(p.Server.UseWicket()(mux)))
	t.Cleanup(h.server.Close)
	return h
}

// loadThroughStore reads the client the way any wicket component does.
func (h *host) loadThroughStore(r *http.Request, id string) error {
	store := godi.GetRequired[storage.ClientStore](hosting.ScopeFrom(r.Context()))
	_, err := store.FindClientById(r.Context(), id)
	return err
}

type outcome struct {
	status   int
	header   http.Header
	body     string
	location *url.URL
	err      error
	storeErr error
	issuer   string
}

func (h *host) initiate(t *testing.T, clientId string) outcome {
	t.Helper()
	query := url.Values{
		"client_id":       {clientId},
		"login_hint":      {loginHint},
		"target_link_uri": {targetLinkUri},
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(h.server.URL + initiatePath + "?" + query.Encode())
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	result := outcome{status: resp.StatusCode, header: resp.Header, body: string(body)}
	if location := resp.Header.Get("Location"); location != "" {
		result.location, err = url.Parse(location)
		require.NoError(t, err)
	}
	h.mu.Lock()
	result.err = h.lastErr
	result.storeErr = h.storeError
	result.issuer = h.issuer
	h.mu.Unlock()
	return result
}

func TestInitiateRedirectsToRegisteredUri(t *testing.T) {
	t.Parallel()
	for name, injected := range map[string]bool{"static clients": false, "injected store": true} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h := newHost(t, injected, issuer)
			got := h.initiate(t, registeredId)
			a := require.New(t)
			a.NoError(got.err)
			a.Equal(http.StatusFound, got.status)
			a.Equal("no-store", got.header.Get("Cache-Control"))
			a.NotNil(got.location)
			a.Equal("https", got.location.Scheme)
			a.Equal("rp.example", got.location.Host)
			a.Equal("/login", got.location.Path)
			a.Equal(url.Values{
				"tenant":          {"a"},
				"iss":             {issuer},
				"login_hint":      {loginHint},
				"target_link_uri": {targetLinkUri},
			}, got.location.Query())
		})
	}
}

func TestInitiateRejectsUnusableClient(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		clientId     string
		want         error
		rejected     bool
		injectedOnly bool
	}{
		"unknown":        {clientId: "missing", want: storage.ErrNotFound, rejected: true},
		"disabled":       {clientId: disabledId, want: storage.ErrNotFound, rejected: true},
		"http uri":       {clientId: httpId, want: storage.ErrInvalidClientConfiguration, rejected: true, injectedOnly: true},
		"not registered": {clientId: unregisteredId, want: thirdpartylogin.ErrNotRegistered},
	}
	for _, injected := range []bool{false, true} {
		h := newHost(t, injected, issuer)
		for name, tc := range cases {
			if tc.injectedOnly && !injected {
				continue
			}
			label := name
			if injected {
				label += " injected store"
			}
			t.Run(label, func(t *testing.T) {
				got := h.initiate(t, tc.clientId)
				a := require.New(t)
				a.True(errors.Is(got.err, tc.want), "err = %v, want %v", got.err, tc.want)
				a.Equal(tc.rejected, extensions.IsClientRejected(got.err))
				a.False(strings.Contains(got.err.Error(), loginHint), "error text carries the login hint")
				assertNothingWritten(t, got)
			})
		}
	}
}

// TestInjectedClientStoreRejectsHttpInitiateLoginUri covers clients that are
// not visible at assembly: an injected store's client registering an http
// initiate_login_uri is rejected on every read through storage.ClientStore.
func TestInjectedClientStoreRejectsHttpInitiateLoginUri(t *testing.T) {
	t.Parallel()
	h := newHost(t, true, issuer)
	got := h.initiate(t, httpId)
	require.ErrorIs(t, got.storeErr, storage.ErrInvalidClientConfiguration)
	require.True(t, extensions.IsClientRejected(got.storeErr))
}

func TestStaticClientListWithHttpInitiateLoginUriFailsAssembly(t *testing.T) {
	t.Parallel()
	p := integration_common.NewWicketPipeline()
	p.Clients = append(clients(false), initiatingClient(httpId, "http://rp.example/login", true))
	defer func() {
		recovered := recover()
		require.NotNil(t, recovered, "assembly accepted an http initiate_login_uri")
		require.Contains(t, fmt.Sprint(recovered), httpId)
	}()
	p.Initialize()
	t.Cleanup(p.TestServer.Close)
}

func TestInitiateRejectsNonHttpsIssuer(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		// Without IssuerUri the issuer is the origin of the plain http test
		// server.
		"request origin": "",
		"http issuer":    "http://op.example",
	}
	for name, issuerUri := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h := newHost(t, false, issuerUri)
			got := h.initiate(t, registeredId)
			want := issuerUri
			if want == "" {
				want = h.server.URL
			}
			require.Equal(t, want, got.issuer)
			require.ErrorIs(t, got.err, thirdpartylogin.ErrInvalidIssuer)
			assertNothingWritten(t, got)
		})
	}
}

func TestInitiateOutsideRequestScope(t *testing.T) {
	t.Parallel()
	h := newHost(t, false, issuer)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, h.server.URL+initiatePath, nil)
	err := thirdpartylogin.Initiate(recorder, request, registeredId, thirdpartylogin.Parameters{LoginHint: loginHint})
	require.ErrorIs(t, err, thirdpartylogin.ErrNoRequestScope)
	require.Empty(t, recorder.Header())
	require.Zero(t, recorder.Body.Len())
}

// assertNothingWritten checks that the initiation left the response alone:
// the host handler returned without writing, so the server answered with an
// empty 200.
func assertNothingWritten(t *testing.T, got outcome) {
	t.Helper()
	require.Equal(t, http.StatusOK, got.status)
	require.Empty(t, got.header.Get("Location"))
	require.Empty(t, got.header.Get("Cache-Control"))
	require.Empty(t, got.body)
}
