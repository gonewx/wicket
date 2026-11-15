// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package pushedauthorization

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gonewx/godi"
	"github.com/tidwall/gjson"

	"github.com/gonewx/wicket"
	client_messages "github.com/gonewx/wicket/client/messages"
	"github.com/gonewx/wicket/models"
	"github.com/gonewx/wicket/models/messages"
	"github.com/gonewx/wicket/pushedauth"
	"github.com/gonewx/wicket/storage"
	storage_memory "github.com/gonewx/wicket/storage/memory"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/test"
	test_common "github.com/gonewx/wicket/test/common"
	integration_common "github.com/gonewx/wicket/test/integration/common"
	"github.com/gonewx/wicket/utils"
)

const (
	parClient     = "par.client"
	otherClient   = "other.client"
	consentClient = "consent.client"
	forcedClient  = "forced.client"
	shortClient   = "short.client"
	clientSecret  = "secret"
)

func redirectUriOf(clientId string) string { return "https://" + clientId + "/callback" }

// countingStore counts the writes of the real in-memory store it wraps and
// can be told to fail takes.
type countingStore struct {
	*storage_memory.MemoryPushedAuthorizationRequestStore
	writes   atomic.Int64
	failTake atomic.Bool
}

func (s *countingStore) StorePushedAuthorizationRequest(ctx context.Context, key string, request *storage_models.PushedAuthorizationRequest) error {
	s.writes.Add(1)
	return s.MemoryPushedAuthorizationRequestStore.StorePushedAuthorizationRequest(ctx, key, request)
}

func (s *countingStore) TakePushedAuthorizationRequest(ctx context.Context, key string) (*storage_models.PushedAuthorizationRequest, error) {
	if s.failTake.Load() {
		return nil, errTakeUnavailable
	}
	return s.MemoryPushedAuthorizationRequestStore.TakePushedAuthorizationRequest(ctx, key)
}

type takeUnavailable struct{}

func (takeUnavailable) Error() string { return "take unavailable" }

var errTakeUnavailable error = takeUnavailable{}

// recordingParametersStore is the query string authorization parameters
// store that also records every parameter set it was handed.
type recordingParametersStore struct {
	*test_common.QueryStringAuthorizationParametersMessageStore
	mu      sync.Mutex
	written []url.Values
}

func (s *recordingParametersStore) Write(ctx context.Context, message *messages.Message[url.Values]) (string, error) {
	s.mu.Lock()
	s.written = append(s.written, message.Data)
	s.mu.Unlock()
	return s.QueryStringAuthorizationParametersMessageStore.Write(ctx, message)
}

func (s *recordingParametersStore) writes() []url.Values {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]url.Values(nil), s.written...)
}

type scene struct {
	t          *testing.T
	pipeline   *integration_common.WicketPipeline
	store      *countingStore
	clock      *integration_common.AdjustableClock
	parameters *recordingParametersStore
}

type sceneOptions struct {
	disabled        bool
	options         pushedauth.Options
	storeParameters bool
	configure       func(*integration_common.WicketPipeline)
}

func newCodeClient(clientId string) *storage_models.Client {
	client := storage_models.NewClient()
	client.ClientId = clientId
	secret := storage_models.NewSecret()
	secret.Value = utils.Sha256(clientSecret)
	client.ClientSecrets = []*storage_models.Secret{secret}
	if err := client.SetAllowedGrantTypes(wicket.GrantTypesCode); err != nil {
		panic(err)
	}
	client.AllowedScopes = []string{wicket.StandardScopesOpenId}
	client.RequireConsent = false
	client.RequirePkce = false
	client.RedirectUris = []string{redirectUriOf(clientId)}
	return client
}

func newScene(t *testing.T, o sceneOptions) *scene {
	t.Helper()
	s := &scene{
		t:        t,
		pipeline: integration_common.NewWicketPipeline(),
		store:    &countingStore{MemoryPushedAuthorizationRequestStore: storage_memory.NewMemoryPushedAuthorizationRequestStore()},
		clock:    integration_common.NewAdjustableClock(time.Date(2026, 11, 14, 9, 0, 0, 0, time.UTC)),
	}

	consent := newCodeClient(consentClient)
	consent.RequireConsent = true
	short := newCodeClient(shortClient)
	short.RequestUriLifetime = 30
	clients := []*storage_models.Client{newCodeClient(parClient), newCodeClient(otherClient), consent, short}
	if !o.disabled {
		forced := newCodeClient(forcedClient)
		forced.RequirePushedAuthorizationRequests = true
		clients = append(clients, forced)
	}
	s.pipeline.Clients = clients
	s.pipeline.IdentityScopes = append(s.pipeline.IdentityScopes, storage_models.IdentityResourcesOpenId())
	user := test.NewTestUser()
	user.SubjectId = "bob"
	user.Username = "bob"
	s.pipeline.Users = append(s.pipeline.Users, user)
	if o.storeParameters {
		s.parameters = &recordingParametersStore{QueryStringAuthorizationParametersMessageStore: test_common.NewQueryStringAuthorizationParametersMessageStore()}
		s.pipeline.AuthorizationParametersMessageStore = s.parameters
	}

	if !o.disabled {
		options := o.options
		options.Clock = s.clock
		cfg := s.pipeline.Root.ServerConfig()
		cfg.SetPushedAuthorizationRequestStore(s.store)
		cfg.SetPushedAuthorizationDataProtectionProvider(integration_common.NewPushedAuthorizationProtection())
		cfg.EnablePushedAuthorizationRequests(options)
	}
	if o.configure != nil {
		o.configure(s.pipeline)
	}
	s.pipeline.Initialize()
	s.pipeline.BrowserClient.AllowAutoRedirect = false
	t.Cleanup(s.pipeline.TestServer.Close)
	return s
}

// backChannel is a plain client of the test server.
func (s *scene) backChannel() *http.Client {
	return &http.Client{
		Transport:     s.pipeline.TestServer.Client().Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

type reply struct {
	status int
	header http.Header
	body   string
}

func (r reply) field(name string) string { return gjson.Get(r.body, name).String() }

func (r reply) intField(name string) int64 { return gjson.Get(r.body, name).Int() }

// postForm posts values to path, authenticating with Basic credentials
// when clientId is not empty.
func (s *scene) postForm(path string, values url.Values, clientId string, header http.Header) reply {
	s.t.Helper()
	request, err := http.NewRequest(http.MethodPost, s.pipeline.TestServer.URL+path, strings.NewReader(values.Encode()))
	if err != nil {
		s.t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for name, list := range header {
		for _, value := range list {
			request.Header.Add(name, value)
		}
	}
	if clientId != "" {
		request.SetBasicAuth(url.QueryEscape(clientId), url.QueryEscape(clientSecret))
	}
	response, err := s.backChannel().Do(request)
	if err != nil {
		s.t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		s.t.Fatal(err)
	}
	return reply{status: response.StatusCode, header: response.Header, body: string(body)}
}

// authorizationParameters are the parameters a client pushes.
func authorizationParameters(clientId string) url.Values {
	return url.Values{
		wicket.AuthorizeRequestResponseType: {wicket.ResponseTypesCode},
		wicket.AuthorizeRequestScope:        {wicket.StandardScopesOpenId},
		wicket.AuthorizeRequestRedirectUri:  {redirectUriOf(clientId)},
		wicket.AuthorizeRequestState:        {"pushed-state"},
		wicket.AuthorizeRequestNonce:        {"pushed-nonce"},
	}
}

// push pushes the authorization parameters of clientId and returns the
// request_uri.
func (s *scene) push(clientId string) string {
	s.t.Helper()
	r := s.postForm("/"+wicket.ProtocolRoutePathsPushedAuthorization, authorizationParameters(clientId), clientId, nil)
	if r.status != http.StatusCreated {
		s.t.Fatalf("push: status %d body %s", r.status, r.body)
	}
	return r.field("request_uri")
}

// record returns the stored record of requestURI, or nil once it is gone.
func (s *scene) record(requestURI string) *storage_models.PushedAuthorizationRequest {
	s.t.Helper()
	key, err := storage.PushedAuthorizationRequestKey(requestURI)
	if err != nil {
		s.t.Fatal(err)
	}
	record, err := s.store.GetPushedAuthorizationRequest(context.Background(), key)
	if err != nil {
		return nil
	}
	return record
}

// authorizeUrl is the browser's front-channel request for requestURI.
func (s *scene) authorizeUrl(clientId string, requestURI string) string {
	return s.pipeline.TestServer.URL + "/" + wicket.ProtocolRoutePathsAuthorize + "?" + url.Values{
		wicket.AuthorizeRequestClientId:   {clientId},
		wicket.AuthorizeRequestRequestUri: {requestURI},
	}.Encode()
}

// browse requests target with the browser, which follows no redirect, and
// returns the status and the absolute redirect target.
func (s *scene) browse(target string) (int, string) {
	s.t.Helper()
	if strings.HasPrefix(target, "/") {
		target = s.pipeline.TestServer.URL + target
	}
	response, err := s.pipeline.BrowserClient.Get(target)
	if err != nil {
		s.t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	location := response.Header.Get("Location")
	if location != "" {
		if parsed, err := url.Parse(location); err == nil && !parsed.IsAbs() {
			location = s.pipeline.TestServer.URL + location
		}
	}
	return response.StatusCode, location
}

// outcome describes where a front-channel response sent the browser.
type outcome struct {
	status int
	// code is the authorization code delivered to the client, if any.
	code string
	// idToken is the identity token delivered to the client, if any.
	idToken string
	// clientError is the error delivered to the client, if any.
	clientError string
	// pageError is the error shown on the error page, if any.
	pageError string
	// login is the login page redirect target, if any.
	login string
	// consent is the consent page redirect target, if any.
	consent string
}

func (s *scene) follow(status int, location string) outcome {
	s.t.Helper()
	o := outcome{status: status}
	parsed, err := url.Parse(location)
	if location == "" || err != nil {
		return o
	}
	switch {
	case strings.HasPrefix(parsed.Path, integration_common.ErrorPage):
		s.pipeline.ErrorMessage = nil
		s.browse(location)
		if s.pipeline.ErrorMessage != nil {
			o.pageError = s.pipeline.ErrorMessage.Error
		}
	case strings.HasPrefix(parsed.Path, wicket.UIConstantsDefaultRoutePathsLogin), strings.HasPrefix(parsed.Path, "/"+wicket.UIConstantsDefaultRoutePathsLogin):
		o.login = location
	case strings.HasPrefix(parsed.Path, wicket.UIConstantsDefaultRoutePathsConsent), strings.HasPrefix(parsed.Path, "/"+wicket.UIConstantsDefaultRoutePathsConsent):
		o.consent = location
	default:
		response := client_messages.NewAuthorizeResponse(location)
		o.code = response.Code()
		o.idToken = response.IdentityToken()
		o.clientError = response.Error()
	}
	return o
}

// authorize sends the browser to target and reports the outcome.
func (s *scene) authorize(target string) outcome {
	s.t.Helper()
	return s.follow(s.browse(target))
}

func (s *scene) login() {
	s.t.Helper()
	if err := s.pipeline.Login("bob"); err != nil {
		s.t.Fatal(err)
	}
}

// loginThrough signs bob in on the login page target and returns where the
// login page sends the browser back.
func (s *scene) loginThrough(target string) string {
	s.t.Helper()
	principal, err := models.NewLocalUser(models.WithLocalUserSubjectId("bob")).CreatePrincipal()
	if err != nil {
		s.t.Fatal(err)
	}
	s.pipeline.Subject = principal
	status, location := s.browse(target)
	if status != http.StatusFound {
		s.t.Fatalf("login page answered %d", status)
	}
	return location
}

// redeem exchanges code at the token endpoint and returns the reply.
func (s *scene) redeem(clientId string, code string) reply {
	s.t.Helper()
	return s.postForm(integration_common.TokenEndpoint, url.Values{
		"grant_type":   {wicket.GrantTypeAuthorizationCode},
		"code":         {code},
		"redirect_uri": {redirectUriOf(clientId)},
	}, clientId, nil)
}

// returnParameters reads the parameters a login or consent redirect carries
// back, from the inline return URL or from the parameters store handle.
func returnParameters(t *testing.T, target string) url.Values {
	t.Helper()
	parsed, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	returnUrl, err := url.Parse(parsed.Query().Get("returnUrl"))
	if err != nil {
		t.Fatal(err)
	}
	return returnUrl.Query()
}

// allowedReturnKeys are the only parameters a pushed request may carry
// through the browser.
var allowedReturnKeys = map[string]bool{
	wicket.AuthorizeRequestClientId:           true,
	wicket.AuthorizeRequestRequestUri:         true,
	wicket.AuthorizeRequestPushedEntryReceipt: true,
	wicket.SuppressedPrompt:                   true,
}

func assertOnlyHandleParameters(t *testing.T, values url.Values) {
	t.Helper()
	if len(values) == 0 {
		t.Fatal("no parameters carried")
	}
	for key := range values {
		if !allowedReturnKeys[key] {
			t.Fatalf("parameter %q travels through the browser: %v", key, values)
		}
	}
}

func discoveryDocument(t *testing.T, s *scene) map[string]any {
	t.Helper()
	response, err := s.backChannel().Get(s.pipeline.TestServer.URL + integration_common.DiscoveryEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var document map[string]any
	if err := json.NewDecoder(response.Body).Decode(&document); err != nil {
		t.Fatal(err)
	}
	return document
}

// clientStoreLookup resolves the client store of the assembly and looks up
// clientId.
func clientStoreLookup(s *scene, clientId string) error {
	scope := s.pipeline.Root.CreateScope()
	defer func() { _ = scope.Close() }()
	_, err := godi.GetRequired[storage.ClientStore](scope).FindClientById(context.Background(), clientId)
	return err
}
