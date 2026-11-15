// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package pushedauthorization

import (
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/gonewx/godi"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/clientcert"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/pushedauth"
	"github.com/gonewx/wicket/storage"
	integration_common "github.com/gonewx/wicket/test/integration/common"
)

// countingTransport counts the requests that reach it and fails them.
type countingTransport struct{ calls atomic.Int64 }

func (c *countingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	c.calls.Add(1)
	return nil, errors.New("no outbound request expected")
}

// TestNotEnabledAssemblyServesNoPushedAuthorization is not parallel: it
// replaces the transport of http.DefaultClient, which fetches request
// objects by request_uri, to prove a pushed handle is never fetched.
func TestNotEnabledAssemblyServesNoPushedAuthorization(t *testing.T) {
	s := newScene(t, sceneOptions{disabled: true, configure: func(p *integration_common.WicketPipeline) {
		godi.GetRequired[*config_options.WicketOptions](p.Root).Endpoints.EnableJwtRequestUri = true
	}})

	for _, path := range []string{wicket.ProtocolRoutePathsPushedAuthorization, wicket.ProtocolRoutePathsMtlsPushedAuthorization} {
		r := s.postForm("/"+path, authorizationParameters(parClient), parClient, nil)
		if r.status != http.StatusNotFound {
			t.Fatalf("%s: status %d, want 404", path, r.status)
		}
	}
	document := discoveryDocument(t, s)
	for _, key := range []string{wicket.DiscoveryPushedAuthorizationRequestEndpoint, wicket.DiscoveryRequirePushedAuthorizationRequests} {
		if _, ok := document[key]; ok {
			t.Fatalf("discovery advertises %s", key)
		}
	}

	transport := &countingTransport{}
	previous := http.DefaultClient.Transport
	http.DefaultClient.Transport = transport
	t.Cleanup(func() { http.DefaultClient.Transport = previous })

	s.login()
	o := s.authorize(s.authorizeUrl(parClient, storage.PushedAuthorizationRequestURIPrefix+"never-pushed"))
	if o.code != "" || o.pageError != wicket.AuthorizeErrorsInvalidRequestUri.Error() {
		t.Fatalf("outcome = %+v, want invalid_request_uri", o)
	}
	if calls := transport.calls.Load(); calls != 0 {
		t.Fatalf("pushed handle fetched %d times", calls)
	}

	// A remote request_uri is still fetched as before.
	values := authorizationParameters(parClient)
	values.Set(wicket.AuthorizeRequestClientId, parClient)
	values.Set(wicket.AuthorizeRequestRequestUri, "https://rp.example/request.jwt")
	s.authorize(s.pipeline.TestServer.URL + "/" + wicket.ProtocolRoutePathsAuthorize + "?" + values.Encode())
	if calls := transport.calls.Load(); calls != 1 {
		t.Fatalf("remote request_uri fetched %d times, want 1", calls)
	}

	// The seams were never asked for.
	if s.store.writes.Load() != 0 {
		t.Fatal("store used while the feature is disabled")
	}
}

func TestClientRequiringPushWithoutTheFeatureIsInvalid(t *testing.T) {
	t.Parallel()
	s := newScene(t, sceneOptions{disabled: true, configure: func(p *integration_common.WicketPipeline) {
		forced := newCodeClient(forcedClient)
		forced.RequirePushedAuthorizationRequests = true
		p.Clients = append(p.Clients, forced)
	}})
	if err := clientStoreLookup(s, forcedClient); !errors.Is(err, storage.ErrInvalidClientConfiguration) {
		t.Fatalf("FindClientById = %v, want ErrInvalidClientConfiguration", err)
	}
	if err := clientStoreLookup(s, parClient); err != nil {
		t.Fatalf("FindClientById(%s) = %v", parClient, err)
	}
}

func TestDiscoveryAdvertisesPushedAuthorization(t *testing.T) {
	t.Parallel()
	s := newScene(t, sceneOptions{options: pushedauth.Options{RequireForAllClients: true}, configure: func(p *integration_common.WicketPipeline) {
		godi.GetRequired[*config_options.WicketOptions](p.Root).MutualTls.Enabled = true
		p.Root.ServerConfig().EnableClientCertificateAuthentication(clientcert.Options{TrustedAuthorities: x509.NewCertPool()})
	}})
	document := discoveryDocument(t, s)

	endpoint, _ := document[wicket.DiscoveryPushedAuthorizationRequestEndpoint].(string)
	if endpoint != s.pipeline.TestServer.URL+"/"+wicket.ProtocolRoutePathsPushedAuthorization {
		t.Fatalf("endpoint = %q", endpoint)
	}
	if document[wicket.DiscoveryRequirePushedAuthorizationRequests] != true {
		t.Fatalf("requirement = %v", document[wicket.DiscoveryRequirePushedAuthorizationRequests])
	}
	aliases, _ := document[wicket.DiscoveryMtlsEndpointAliases].(map[string]any)
	alias, _ := aliases[wicket.DiscoveryPushedAuthorizationRequestEndpoint].(string)
	if alias != s.pipeline.TestServer.URL+"/"+wicket.ProtocolRoutePathsMtlsPushedAuthorization {
		t.Fatalf("alias = %q (aliases %v)", alias, aliases)
	}

	for _, target := range []string{endpoint, alias} {
		request, err := http.NewRequest(http.MethodPost, target, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response, err := s.backChannel().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		if response.StatusCode == http.StatusNotFound {
			t.Fatalf("%s is not routed", target)
		}
	}
}

func TestMtlsAliasIsNotServedWithoutMutualTls(t *testing.T) {
	t.Parallel()
	s := newScene(t, sceneOptions{})
	r := s.postForm("/"+wicket.ProtocolRoutePathsMtlsPushedAuthorization, authorizationParameters(parClient), parClient, nil)
	if r.status != http.StatusNotFound {
		t.Fatalf("status %d, want 404", r.status)
	}
	if writes := s.store.writes.Load(); writes != 0 {
		t.Fatalf("store written %d times", writes)
	}
	if r := s.postForm("/"+wicket.ProtocolRoutePathsPushedAuthorization, authorizationParameters(parClient), parClient, nil); r.status != http.StatusCreated {
		t.Fatalf("main route: status %d body %s", r.status, r.body)
	}
}
