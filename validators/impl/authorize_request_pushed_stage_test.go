// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"reflect"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/gonewx/wicket"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/pushedauth"
	services_impl "github.com/gonewx/wicket/services/impl"
	"github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/storage/memory"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/validators"
	validators_mock "github.com/gonewx/wicket/validators/mock"
)

// countingRequestUriFetcher counts request_uri fetches and serves nothing.
type countingRequestUriFetcher struct{ calls atomic.Int64 }

func (f *countingRequestUriFetcher) GetJwt(string, *storage_models.Client) (string, error) {
	f.calls.Add(1)
	return "", errors.New("no request object here")
}

// fakePushedResolver resolves one request_uri to fixed parameters.
type fakePushedResolver struct {
	requestURI  string
	parameters  url.Values
	receipt     string
	err         error
	required    bool
	calls       int
	lastReceipt string
	lastReturn  bool
}

func (r *fakePushedResolver) Resolve(_ context.Context, requestURI string, clientId string, receipt string, interactionReturn bool) (url.Values, string, error) {
	r.calls++
	r.lastReceipt = receipt
	r.lastReturn = interactionReturn
	if r.err != nil {
		return nil, "", r.err
	}
	if requestURI != r.requestURI || clientId != r.parameters.Get(wicket.AuthorizeRequestClientId) {
		return nil, "", pushedauth.ErrRequestUriInvalid
	}
	if interactionReturn && receipt != "" {
		return cloneValues(r.parameters), receipt, nil
	}
	return cloneValues(r.parameters), r.receipt, nil
}

func (r *fakePushedResolver) Required(*storage_models.Client) bool { return r.required }

const pushedTestURI = storage.PushedAuthorizationRequestURIPrefix + "pushed-test-handle"

func pushedCodeParameters() url.Values {
	return url.Values{
		wicket.AuthorizeRequestClientId:     {"codeclient"},
		wicket.AuthorizeRequestScope:        {"openid"},
		wicket.AuthorizeRequestRedirectUri:  {"https://server/cb"},
		wicket.AuthorizeRequestResponseType: {wicket.ResponseTypesCode},
		wicket.AuthorizeRequestState:        {"pushed-state"},
	}
}

func newPushedTestValidator(t *testing.T, resolver PushedAuthorizationResolver) (*AuthorizeRequestValidator, *countingRequestUriFetcher) {
	t.Helper()
	options := config_options.NewWicketOptions()
	options.Endpoints.EnableJwtRequestUri = true
	clientStore, err := memory.NewMemoryClientStore(validators_mock.TestClients{}.Get())
	if err != nil {
		t.Fatal(err)
	}
	scopes := &validators_mock.TestScopes{}
	resourceStore, err := memory.NewMemoryResourcesStore(scopes.GetIdentity(), scopes.GetApis(), scopes.GetScopes())
	if err != nil {
		t.Fatal(err)
	}
	fetcher := &countingRequestUriFetcher{}
	validator := NewAuthorizeRequestValidator(
		slog.Default(),
		options,
		services_impl.NewIssuerNameService(options),
		clientStore,
		fetcher,
		nil,
		NewStrictRedirectUriValidator(),
		NewResourceValidator(resourceStore, NewScopeParser(), slog.Default()),
		nil,
		NewCustomAuthorizeRequestValidator(),
	)
	if resolver != nil {
		validator.SetPushedAuthorization(NewAuthorizeRequestPushedStage(resolver))
	}
	return validator, fetcher
}

func TestPushedStageResolvesWithoutFetching(t *testing.T) {
	t.Parallel()
	resolver := &fakePushedResolver{requestURI: pushedTestURI, parameters: pushedCodeParameters(), receipt: "issued-receipt"}
	validator, fetcher := newPushedTestValidator(t, resolver)

	presented := url.Values{
		wicket.AuthorizeRequestClientId:           {"codeclient"},
		wicket.AuthorizeRequestRequestUri:         {pushedTestURI},
		wicket.AuthorizeRequestState:              {"outer-state"},
		wicket.SuppressedPrompt:                   {"login"},
		wicket.AuthorizeRequestPushedEntryReceipt: {"issued-receipt"},
	}
	before := cloneValues(presented)

	result := validator.Validate(context.Background(), presented, nil, validators.AuthorizeRequestPhaseInteractionReturn)
	if result.Error != nil {
		t.Fatalf("Validate error = %v (%s)", result.Error, result.Description)
	}
	if fetcher.calls.Load() != 0 {
		t.Fatalf("request_uri fetched %d times", fetcher.calls.Load())
	}
	if !reflect.DeepEqual(presented, before) {
		t.Fatalf("presented values changed: %v", presented)
	}
	request := result.ValidatedRequest
	if request.State != "pushed-state" {
		t.Errorf("State = %q, want the pushed value", request.State)
	}
	if request.PushedRequestUri != pushedTestURI {
		t.Errorf("PushedRequestUri = %q", request.PushedRequestUri)
	}
	if request.PushedParameters.Get(wicket.AuthorizeRequestRedirectUri) != "https://server/cb" {
		t.Errorf("PushedParameters = %v", request.PushedParameters)
	}
	if request.PushedParameters.Get(wicket.SuppressedPrompt) != "login" {
		t.Errorf("suppressed prompt not carried into the working set: %v", request.PushedParameters)
	}
	wantRaw := url.Values{
		wicket.AuthorizeRequestClientId:           {"codeclient"},
		wicket.AuthorizeRequestRequestUri:         {pushedTestURI},
		wicket.AuthorizeRequestPushedEntryReceipt: {"issued-receipt"},
		wicket.SuppressedPrompt:                   {"login"},
	}
	if !reflect.DeepEqual(request.Raw, wantRaw) {
		t.Errorf("Raw = %v, want %v", request.Raw, wantRaw)
	}
	if !reflect.DeepEqual(request.ToOptimizedRawValues(), wantRaw) {
		t.Errorf("ToOptimizedRawValues = %v", request.ToOptimizedRawValues())
	}
	// A prompt suppressed after validation lands in Raw, not in the
	// pushed parameters.
	request.RemovePrompt()
	if _, ok := request.PushedParameters[wicket.AuthorizeRequestPushedEntryReceipt]; ok {
		t.Error("receipt leaked into the pushed parameters")
	}
}

func TestPushedStageSwapsOnFailureAfterBinding(t *testing.T) {
	t.Parallel()
	parameters := pushedCodeParameters()
	parameters.Set(wicket.AuthorizeRequestRedirectUri, "https://unregistered/cb")
	resolver := &fakePushedResolver{requestURI: pushedTestURI, parameters: parameters, receipt: "r"}
	validator, _ := newPushedTestValidator(t, resolver)

	result := validator.Validate(context.Background(), url.Values{
		wicket.AuthorizeRequestClientId:   {"codeclient"},
		wicket.AuthorizeRequestRequestUri: {pushedTestURI},
	}, nil, validators.AuthorizeRequestPhaseEntry)
	if !errors.Is(result.Error, wicket.AuthorizeErrorsInvalidRequest) {
		t.Fatalf("Validate error = %v, want invalid_request", result.Error)
	}
	request := result.ValidatedRequest
	if request.PushedRequestUri != pushedTestURI {
		t.Fatalf("PushedRequestUri = %q after a failure past binding", request.PushedRequestUri)
	}
	keys := slices.Sorted(func(yield func(string) bool) {
		for key := range request.Raw {
			if !yield(key) {
				return
			}
		}
	})
	want := []string{wicket.AuthorizeRequestClientId, wicket.AuthorizeRequestPushedEntryReceipt, wicket.AuthorizeRequestRequestUri}
	slices.Sort(want)
	if !slices.Equal(keys, want) {
		t.Fatalf("Raw keys = %v, want %v", keys, want)
	}
}

func TestPushedStageInteractionReturnPassesReceipt(t *testing.T) {
	t.Parallel()
	resolver := &fakePushedResolver{requestURI: pushedTestURI, parameters: pushedCodeParameters(), receipt: "fresh"}
	validator, _ := newPushedTestValidator(t, resolver)
	result := validator.Validate(context.Background(), url.Values{
		wicket.AuthorizeRequestClientId:           {"codeclient"},
		wicket.AuthorizeRequestRequestUri:         {pushedTestURI},
		wicket.AuthorizeRequestPushedEntryReceipt: {"carried"},
	}, nil, validators.AuthorizeRequestPhaseInteractionReturn)
	if result.Error != nil {
		t.Fatalf("Validate error = %v", result.Error)
	}
	if !resolver.lastReturn || resolver.lastReceipt != "carried" {
		t.Fatalf("resolver saw return=%v receipt=%q", resolver.lastReturn, resolver.lastReceipt)
	}
	if got := result.ValidatedRequest.Raw.Get(wicket.AuthorizeRequestPushedEntryReceipt); got != "carried" {
		t.Fatalf("receipt in Raw = %q, want the carried one", got)
	}

	// The authorize endpoint declares an entry even when a receipt is
	// presented.
	validator.Validate(context.Background(), url.Values{
		wicket.AuthorizeRequestClientId:           {"codeclient"},
		wicket.AuthorizeRequestRequestUri:         {pushedTestURI},
		wicket.AuthorizeRequestPushedEntryReceipt: {"carried"},
	}, nil, validators.AuthorizeRequestPhaseEntry)
	if resolver.lastReturn {
		t.Fatal("entry phase passed as interaction return")
	}
}

func TestPushedStageRejections(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		resolver *fakePushedResolver
		noStage  bool
		phase    validators.AuthorizeRequestPhase
		values   url.Values
		wantErr  error
	}{
		"pushed request_uri while disabled": {
			noStage: true,
			values:  url.Values{wicket.AuthorizeRequestClientId: {"codeclient"}, wicket.AuthorizeRequestRequestUri: {pushedTestURI}},
			wantErr: wicket.AuthorizeErrorsInvalidRequestUri,
		},
		"unknown pushed request_uri": {
			resolver: &fakePushedResolver{requestURI: pushedTestURI, parameters: pushedCodeParameters()},
			values:   url.Values{wicket.AuthorizeRequestClientId: {"codeclient"}, wicket.AuthorizeRequestRequestUri: {pushedTestURI + "x"}},
			wantErr:  wicket.AuthorizeErrorsInvalidRequestUri,
		},
		"store failure": {
			resolver: &fakePushedResolver{err: errors.New("boom")},
			values:   url.Values{wicket.AuthorizeRequestClientId: {"codeclient"}, wicket.AuthorizeRequestRequestUri: {pushedTestURI}},
			wantErr:  wicket.AuthorizeErrorsServerError,
		},
		"push carrying request_uri": {
			resolver: &fakePushedResolver{},
			phase:    validators.AuthorizeRequestPhasePush,
			values: func() url.Values {
				v := pushedCodeParameters()
				v.Set(wicket.AuthorizeRequestRequestUri, "https://rp.example/r")
				return v
			}(),
			wantErr: wicket.AuthorizeErrorsInvalidRequest,
		},
		"required but not pushed": {
			resolver: &fakePushedResolver{required: true},
			values:   pushedCodeParameters(),
			wantErr:  wicket.AuthorizeErrorsInvalidRequest,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var resolver PushedAuthorizationResolver
			if !tc.noStage {
				resolver = tc.resolver
			}
			validator, fetcher := newPushedTestValidator(t, resolver)
			result := validator.Validate(context.Background(), tc.values, nil, tc.phase)
			if !errors.Is(result.Error, tc.wantErr) {
				t.Fatalf("Validate error = %v, want %v", result.Error, tc.wantErr)
			}
			if fetcher.calls.Load() != 0 {
				t.Fatalf("request_uri fetched %d times", fetcher.calls.Load())
			}
			if result.ValidatedRequest.PushedRequestUri != "" {
				t.Fatal("request bound although resolution failed")
			}
		})
	}
}

func TestPushedStageLeavesOrdinaryRequestsAlone(t *testing.T) {
	t.Parallel()
	validator, _ := newPushedTestValidator(t, &fakePushedResolver{})
	for _, phase := range []validators.AuthorizeRequestPhase{validators.AuthorizeRequestPhaseEntry, validators.AuthorizeRequestPhasePush} {
		result := validator.Validate(context.Background(), pushedCodeParameters(), nil, phase)
		if result.Error != nil {
			t.Fatalf("phase %d: Validate error = %v", phase, result.Error)
		}
		if result.ValidatedRequest.PushedRequestUri != "" || result.ValidatedRequest.Raw.Get(wicket.AuthorizeRequestState) != "pushed-state" {
			t.Fatalf("phase %d: ordinary request changed: %+v", phase, result.ValidatedRequest.Raw)
		}
	}
}

func TestPushedStageIgnoresSuppressedPromptOnEntry(t *testing.T) {
	t.Parallel()
	parameters := pushedCodeParameters()
	parameters.Set(wicket.AuthorizeRequestPrompt, wicket.PromptModesLogin)
	tests := map[string]struct {
		phase   validators.AuthorizeRequestPhase
		receipt string
	}{
		"entry":                          {phase: validators.AuthorizeRequestPhaseEntry, receipt: "issued-receipt"},
		"interaction return, no receipt": {phase: validators.AuthorizeRequestPhaseInteractionReturn},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			resolver := &fakePushedResolver{requestURI: pushedTestURI, parameters: parameters, receipt: "issued-receipt"}
			validator, _ := newPushedTestValidator(t, resolver)
			presented := url.Values{
				wicket.AuthorizeRequestClientId:   {"codeclient"},
				wicket.AuthorizeRequestRequestUri: {pushedTestURI},
				wicket.SuppressedPrompt:           {wicket.PromptModesLogin},
			}
			if tc.receipt != "" {
				presented.Set(wicket.AuthorizeRequestPushedEntryReceipt, tc.receipt)
			}
			result := validator.Validate(context.Background(), presented, nil, tc.phase)
			if result.Error != nil {
				t.Fatalf("Validate error = %v", result.Error)
			}
			request := result.ValidatedRequest
			if !slices.Contains(request.PromptModes, wicket.PromptModesLogin) {
				t.Fatalf("PromptModes = %v, the pushed prompt=login was suppressed", request.PromptModes)
			}
			if request.PushedParameters.Has(wicket.SuppressedPrompt) || request.Raw.Has(wicket.SuppressedPrompt) {
				t.Fatalf("suppressed prompt marker carried: pushed %v raw %v", request.PushedParameters, request.Raw)
			}
		})
	}
}
