// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package pushedauthorization

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gonewx/wicket"
	models_messages "github.com/gonewx/wicket/models/messages"
	"github.com/gonewx/wicket/pushedauth"
	"github.com/gonewx/wicket/storage"
	integration_common "github.com/gonewx/wicket/test/integration/common"
)

func TestPushReturnsRequestUri(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		clientId      string
		wantExpiresIn int64
		wantLifetime  time.Duration
	}{
		"server lifetime": {clientId: parClient, wantExpiresIn: 60, wantLifetime: 60 * time.Second},
		"client lifetime": {clientId: shortClient, wantExpiresIn: 30, wantLifetime: 30 * time.Second},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s := newScene(t, sceneOptions{})
			r := s.postForm("/"+wicket.ProtocolRoutePathsPushedAuthorization, authorizationParameters(tc.clientId), tc.clientId, nil)
			if r.status != http.StatusCreated {
				t.Fatalf("status %d body %s", r.status, r.body)
			}
			if got := r.header.Get("Content-Type"); got != "application/json" {
				t.Errorf("Content-Type = %q", got)
			}
			if got := r.header.Get("Cache-Control"); !strings.Contains(got, "no-store") {
				t.Errorf("Cache-Control = %q", got)
			}
			requestURI := r.field("request_uri")
			if !strings.HasPrefix(requestURI, storage.PushedAuthorizationRequestURIPrefix) {
				t.Fatalf("request_uri = %q", requestURI)
			}
			if got := r.intField("expires_in"); got != tc.wantExpiresIn {
				t.Fatalf("expires_in = %d, want %d", got, tc.wantExpiresIn)
			}
			record := s.record(requestURI)
			if record == nil {
				t.Fatal("no record stored")
			}
			if !record.EntryExpiration.Equal(s.clock.Now().Add(tc.wantLifetime)) {
				t.Fatalf("EntryExpiration = %v", record.EntryExpiration)
			}
		})
	}
}

func TestPushIsRefused(t *testing.T) {
	t.Parallel()
	path := "/" + wicket.ProtocolRoutePathsPushedAuthorization
	tests := map[string]struct {
		send       func(s *scene) reply
		wantStatus []int
		wantError  string
	}{
		"get": {
			send: func(s *scene) reply {
				response, err := s.backChannel().Get(s.pipeline.TestServer.URL + path)
				if err != nil {
					t.Fatal(err)
				}
				_ = response.Body.Close()
				return reply{status: response.StatusCode}
			},
			wantStatus: []int{http.StatusMethodNotAllowed},
		},
		"no authentication": {
			send: func(s *scene) reply {
				values := authorizationParameters(parClient)
				values.Set(wicket.AuthorizeRequestClientId, parClient)
				return s.postForm(path, values, "", nil)
			},
			wantStatus: []int{http.StatusBadRequest, http.StatusUnauthorized},
			wantError:  "invalid_client",
		},
		"wrong secret": {
			send: func(s *scene) reply {
				values := authorizationParameters(parClient)
				values.Set(wicket.AuthorizeRequestClientId, parClient)
				values.Set("client_secret", "wrong")
				return s.postForm(path, values, "", nil)
			},
			wantStatus: []int{http.StatusBadRequest, http.StatusUnauthorized},
			wantError:  "invalid_client",
		},
		"request_uri in the push": {
			send: func(s *scene) reply {
				values := authorizationParameters(parClient)
				values.Set(wicket.AuthorizeRequestRequestUri, storage.PushedAuthorizationRequestURIPrefix+"nested")
				return s.postForm(path, values, parClient, nil)
			},
			wantStatus: []int{http.StatusBadRequest},
			wantError:  "invalid_request",
		},
		"unregistered redirect_uri": {
			send: func(s *scene) reply {
				values := authorizationParameters(parClient)
				values.Set(wicket.AuthorizeRequestRedirectUri, "https://attacker.example/callback")
				return s.postForm(path, values, parClient, nil)
			},
			wantStatus: []int{http.StatusBadRequest},
			wantError:  "invalid_request",
		},
		"client_id of another client": {
			send: func(s *scene) reply {
				values := authorizationParameters(parClient)
				values.Set(wicket.AuthorizeRequestClientId, otherClient)
				return s.postForm(path, values, parClient, nil)
			},
			wantStatus: []int{http.StatusBadRequest},
			wantError:  "invalid_request",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s := newScene(t, sceneOptions{})
			r := tc.send(s)
			ok := false
			for _, status := range tc.wantStatus {
				ok = ok || r.status == status
			}
			if !ok {
				t.Fatalf("status %d body %s, want one of %v", r.status, r.body, tc.wantStatus)
			}
			if tc.wantError != "" && r.field("error") != tc.wantError {
				t.Fatalf("error = %q, want %q (%s)", r.field("error"), tc.wantError, r.body)
			}
			if writes := s.store.writes.Load(); writes != 0 {
				t.Fatalf("store written %d times", writes)
			}
		})
	}
}

func TestPushedRequestCompletesTheFlow(t *testing.T) {
	t.Parallel()
	s := newScene(t, sceneOptions{})
	requestURI := s.push(parClient)
	s.login()

	o := s.authorize(s.authorizeUrl(parClient, requestURI))
	if o.code == "" {
		t.Fatalf("no code: %+v", o)
	}
	if s.record(requestURI) != nil {
		t.Fatal("record still stored after the code was issued")
	}
	r := s.redeem(parClient, o.code)
	if r.status != http.StatusOK || r.field("access_token") == "" {
		t.Fatalf("redeem: status %d body %s", r.status, r.body)
	}

	// The handle cannot be presented again.
	replay := s.authorize(s.authorizeUrl(parClient, requestURI))
	if replay.code != "" {
		t.Fatalf("replayed request_uri issued a code: %+v", replay)
	}
	if replay.pageError != wicket.AuthorizeErrorsInvalidRequestUri.Error() {
		t.Fatalf("replay outcome = %+v, want invalid_request_uri", replay)
	}
}

func TestExpiredEntryIsRefused(t *testing.T) {
	t.Parallel()
	s := newScene(t, sceneOptions{})
	requestURI := s.push(parClient)
	s.login()
	s.clock.Advance(61 * time.Second)

	o := s.authorize(s.authorizeUrl(parClient, requestURI))
	if o.code != "" || o.pageError != wicket.AuthorizeErrorsInvalidRequestUri.Error() {
		t.Fatalf("outcome = %+v, want invalid_request_uri without code", o)
	}
	if s.record(requestURI) == nil {
		t.Fatal("expired entry consumed the record")
	}
}

func TestSlowLoginCompletesWithinRetention(t *testing.T) {
	t.Parallel()
	for _, stored := range []bool{false, true} {
		name := "inline return url"
		if stored {
			name = "parameters store"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s := newScene(t, sceneOptions{storeParameters: stored})
			requestURI := s.push(parClient)

			o := s.authorize(s.authorizeUrl(parClient, requestURI))
			if o.login == "" {
				t.Fatalf("no login redirect: %+v", o)
			}
			if !stored {
				assertOnlyHandleParameters(t, returnParameters(t, o.login))
			} else {
				for _, written := range s.parameters.writes() {
					assertOnlyHandleParameters(t, written)
				}
			}

			// The user takes five minutes to log in.
			s.clock.Advance(5 * time.Minute)
			back := s.loginThrough(o.login)
			if s.pipeline.LoginRequest == nil {
				t.Fatal("login page could not read the pushed request")
			}
			if s.pipeline.LoginRequest.Client == nil || s.pipeline.LoginRequest.Client.ClientId != parClient {
				t.Fatalf("login request = %+v", s.pipeline.LoginRequest)
			}
			assertOnlyHandleParameters(t, s.pipeline.LoginRequest.Parameters)

			final := s.authorize(back)
			if final.code == "" {
				t.Fatalf("no code after a slow login: %+v", final)
			}
			if s.record(requestURI) != nil {
				t.Fatal("record still stored")
			}
			if r := s.redeem(parClient, final.code); r.status != http.StatusOK {
				t.Fatalf("redeem: status %d body %s", r.status, r.body)
			}
		})
	}
}

func TestCallbackCannotBypassTheEntryLifetime(t *testing.T) {
	t.Parallel()
	tests := map[string]func(s *scene, own url.Values) url.Values{
		"no receipt": func(s *scene, own url.Values) url.Values {
			own.Del(wicket.AuthorizeRequestPushedEntryReceipt)
			return own
		},
		"forged receipt": func(s *scene, own url.Values) url.Values {
			own.Set(wicket.AuthorizeRequestPushedEntryReceipt, "Zm9yZ2VkLXJlY2VpcHQ")
			return own
		},
		"receipt of another request_uri": func(s *scene, own url.Values) url.Values {
			other := s.push(parClient)
			o := s.authorize(s.authorizeUrl(parClient, other))
			if o.login == "" {
				s.t.Fatalf("no login redirect: %+v", o)
			}
			own.Set(wicket.AuthorizeRequestPushedEntryReceipt, returnParameters(s.t, o.login).Get(wicket.AuthorizeRequestPushedEntryReceipt))
			return own
		},
	}
	for name, tamper := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s := newScene(t, sceneOptions{})
			requestURI := s.push(parClient)
			// The handle is presented once, without a login, so the
			// browser holds a genuine return URL for it.
			o := s.authorize(s.authorizeUrl(parClient, requestURI))
			if o.login == "" {
				t.Fatalf("no login redirect: %+v", o)
			}
			own := returnParameters(t, o.login)
			values := tamper(s, own)

			s.login()
			s.clock.Advance(2 * time.Minute)
			callback := s.authorize("/" + wicket.ProtocolRoutePathsAuthorizeCallback + "?" + values.Encode())
			if callback.code != "" {
				t.Fatalf("callback issued a code past the entry lifetime: %+v", callback)
			}
			if callback.pageError != wicket.AuthorizeErrorsInvalidRequestUri.Error() {
				t.Fatalf("callback outcome = %+v, want invalid_request_uri", callback)
			}
			if s.record(requestURI) == nil {
				t.Fatal("refused callback consumed the record")
			}
		})
	}
}

func TestAuthorizeEndpointJudgesReceiptAsEntry(t *testing.T) {
	t.Parallel()
	s := newScene(t, sceneOptions{})
	requestURI := s.push(parClient)
	// The browser holds a genuine return URL with a valid receipt.
	o := s.authorize(s.authorizeUrl(parClient, requestURI))
	if o.login == "" {
		t.Fatalf("no login redirect: %+v", o)
	}
	own := returnParameters(t, o.login)
	if own.Get(wicket.AuthorizeRequestPushedEntryReceipt) == "" {
		t.Fatal("return url carries no receipt")
	}

	s.login()
	// Past the entry lifetime, within retention.
	s.clock.Advance(2 * time.Minute)
	direct := s.authorize("/" + wicket.ProtocolRoutePathsAuthorize + "?" + own.Encode())
	if direct.code != "" {
		t.Fatalf("authorize endpoint issued a code past the entry lifetime: %+v", direct)
	}
	if direct.pageError != wicket.AuthorizeErrorsInvalidRequestUri.Error() {
		t.Fatalf("authorize outcome = %+v, want invalid_request_uri", direct)
	}
	if s.record(requestURI) == nil {
		t.Fatal("refused authorize consumed the record")
	}
}

func TestRequestUriOfAnotherClientIsRefused(t *testing.T) {
	t.Parallel()
	s := newScene(t, sceneOptions{})
	requestURI := s.push(parClient)
	s.login()

	foreign := s.authorize(s.authorizeUrl(otherClient, requestURI))
	if foreign.code != "" || foreign.pageError != wicket.AuthorizeErrorsInvalidRequestUri.Error() {
		t.Fatalf("foreign outcome = %+v, want invalid_request_uri", foreign)
	}
	if s.record(requestURI) == nil {
		t.Fatal("foreign use consumed the record")
	}
	own := s.authorize(s.authorizeUrl(parClient, requestURI))
	if own.code == "" {
		t.Fatalf("owner could not complete: %+v", own)
	}
}

func TestConcurrentUseIssuesOneCode(t *testing.T) {
	t.Parallel()
	s := newScene(t, sceneOptions{})
	requestURI := s.push(parClient)
	s.login()

	const n = 8
	target := s.authorizeUrl(parClient, requestURI)
	locations := make([]string, n)
	statuses := make([]int, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			response, err := s.pipeline.BrowserClient.Get(target)
			if err != nil {
				t.Error(err)
				return
			}
			_ = response.Body.Close()
			statuses[i] = response.StatusCode
			locations[i] = response.Header.Get("Location")
		}()
	}
	close(start)
	wg.Wait()

	codes := 0
	for i := range n {
		parsed, err := url.Parse(locations[i])
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(locations[i], redirectUriOf(parClient)) {
			if parsed.Query().Get("code") != "" {
				codes++
				continue
			}
			if got := parsed.Query().Get("error"); got != wicket.AuthorizeErrorsInvalidRequest.Error() {
				t.Errorf("loser %d got error %q, want invalid_request", i, got)
			}
			continue
		}
		if !strings.HasPrefix(parsed.Path, wicket.UIConstantsDefaultRoutePathsError) {
			t.Errorf("request %d: status %d location %q", i, statuses[i], locations[i])
		}
	}
	if codes != 1 {
		t.Fatalf("%d requests received a code, want exactly 1 (%v)", codes, locations)
	}
}

func TestRequiredPushIsEnforced(t *testing.T) {
	t.Parallel()
	plain := func(s *scene, clientId string) outcome {
		values := authorizationParameters(clientId)
		values.Set(wicket.AuthorizeRequestClientId, clientId)
		return s.authorize(s.pipeline.TestServer.URL + "/" + wicket.ProtocolRoutePathsAuthorize + "?" + values.Encode())
	}

	t.Run("client requirement", func(t *testing.T) {
		t.Parallel()
		s := newScene(t, sceneOptions{})
		s.login()
		if o := plain(s, forcedClient); o.code != "" || o.pageError != wicket.AuthorizeErrorsInvalidRequest.Error() {
			t.Fatalf("outcome = %+v, want invalid_request", o)
		}
		if o := plain(s, parClient); o.code == "" {
			t.Fatalf("a client without the requirement was refused: %+v", o)
		}
		if o := s.authorize(s.authorizeUrl(forcedClient, s.push(forcedClient))); o.code == "" {
			t.Fatalf("a pushed request of the forced client was refused: %+v", o)
		}
	})
	t.Run("server requirement", func(t *testing.T) {
		t.Parallel()
		s := newScene(t, sceneOptions{options: pushedauth.Options{RequireForAllClients: true}})
		s.login()
		if o := plain(s, parClient); o.code != "" || o.pageError != wicket.AuthorizeErrorsInvalidRequest.Error() {
			t.Fatalf("outcome = %+v, want invalid_request", o)
		}
		if o := s.authorize(s.authorizeUrl(parClient, s.push(parClient))); o.code == "" {
			t.Fatalf("a pushed request was refused: %+v", o)
		}
	})
}

func TestNegativeClientLifetimeIsInvalidConfiguration(t *testing.T) {
	t.Parallel()
	s := newScene(t, sceneOptions{configure: func(p *integration_common.WicketPipeline) {
		p.Clients[0].RequestUriLifetime = -1
	}})
	if err := clientStoreLookup(s, parClient); !errors.Is(err, storage.ErrInvalidClientConfiguration) {
		t.Fatalf("FindClientById = %v, want ErrInvalidClientConfiguration", err)
	}
}

func TestDeletedClientIsRefused(t *testing.T) {
	t.Parallel()
	s := newScene(t, sceneOptions{})
	requestURI := s.push(parClient)
	s.login()
	s.pipeline.Clients = s.pipeline.Clients[1:]

	o := s.authorize(s.authorizeUrl(parClient, requestURI))
	if o.code != "" {
		t.Fatalf("deleted client received a code: %+v", o)
	}
}

func TestConsumptionFailureIssuesNoCode(t *testing.T) {
	t.Parallel()
	s := newScene(t, sceneOptions{})
	requestURI := s.push(parClient)
	s.login()
	s.store.failTake.Store(true)

	status, location := s.browse(s.authorizeUrl(parClient, requestURI))
	if status < 500 {
		t.Fatalf("status %d location %q, want a server error", status, location)
	}
	if strings.Contains(location, "code=") {
		t.Fatalf("code issued: %s", location)
	}
	if s.record(requestURI) == nil {
		t.Fatal("record gone although the take failed")
	}
}

func TestConsentRoundTripKeepsTheConsentKey(t *testing.T) {
	t.Parallel()
	for _, stored := range []bool{false, true} {
		name := "inline return url"
		if stored {
			name = "parameters store"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s := newScene(t, sceneOptions{storeParameters: stored})
			requestURI := s.push(consentClient)
			s.login()

			o := s.authorize(s.authorizeUrl(consentClient, requestURI))
			if o.consent == "" {
				t.Fatalf("no consent redirect: %+v", o)
			}
			if stored {
				writes := s.parameters.writes()
				if len(writes) == 0 {
					t.Fatal("parameters store not used")
				}
				for _, written := range writes {
					assertOnlyHandleParameters(t, written)
				}
			} else {
				assertOnlyHandleParameters(t, returnParameters(t, o.consent))
			}

			s.pipeline.ConsentResponse = models_messages.NewConsentResponse()
			s.pipeline.ConsentResponse.ScopesValuesConsented = []string{wicket.StandardScopesOpenId}
			status, back := s.browse(o.consent)
			if status != http.StatusFound {
				t.Fatalf("consent page answered %d", status)
			}
			if s.pipeline.ConsentRequest == nil {
				t.Fatal("consent page could not read the pushed request")
			}
			assertOnlyHandleParameters(t, s.pipeline.ConsentRequest.Parameters)

			final := s.authorize(back)
			if final.code == "" {
				t.Fatalf("no code after consent: %+v", final)
			}
			if r := s.redeem(consentClient, final.code); r.status != http.StatusOK {
				t.Fatalf("redeem: status %d body %s", r.status, r.body)
			}
		})
	}
}

func TestPushedHybridRequestCarriesTheNonce(t *testing.T) {
	t.Parallel()
	const hybridClient = "hybrid.client"
	s := newScene(t, sceneOptions{configure: func(p *integration_common.WicketPipeline) {
		hybrid := newCodeClient(hybridClient)
		if err := hybrid.SetAllowedGrantTypes(wicket.GrantTypesHybrid); err != nil {
			t.Fatal(err)
		}
		p.Clients = append(p.Clients, hybrid)
	}})
	values := authorizationParameters(hybridClient)
	values.Set(wicket.AuthorizeRequestResponseType, wicket.ResponseTypesCodeIdToken)
	values.Set(wicket.AuthorizeRequestNonce, "pushed-hybrid-nonce")
	r := s.postForm("/"+wicket.ProtocolRoutePathsPushedAuthorization, values, hybridClient, nil)
	if r.status != http.StatusCreated {
		t.Fatalf("push: status %d body %s", r.status, r.body)
	}
	s.login()

	o := s.authorize(s.authorizeUrl(hybridClient, r.field("request_uri")))
	if o.code == "" || o.idToken == "" {
		t.Fatalf("outcome = %+v, want a code and an id_token", o)
	}
	parts := strings.Split(o.idToken, ".")
	if len(parts) != 3 {
		t.Fatalf("id_token %q is not a JWS", o.idToken)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["nonce"] != "pushed-hybrid-nonce" {
		t.Fatalf("nonce = %v, want the pushed value", claims["nonce"])
	}
}
