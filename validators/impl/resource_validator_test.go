// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"log/slog"
	"reflect"
	"sort"
	"testing"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/storage/memory"
	storage_models "github.com/gonewx/wicket/storage/models"
	validators_models "github.com/gonewx/wicket/validators/models"
)

const (
	resourceOrders   = "https://resources.example.com/orders"
	resourcePayments = "https://resources.example.com/payments"
	resourceCommon   = "https://resources.example.com/common"
)

func TestResourceValidatorTable(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		clientScopes       []string
		scopes             []string
		resources          []string
		includeNonIsolated bool
		wantSucceeded      bool
		wantInvalidScopes  []string
		wantInvalidTargets []string
		wantApiResources   []string
		wantApiScopes      []string
	}{
		"valid selected resource": {
			clientScopes:     []string{"orders.read"},
			scopes:           []string{"orders.read"},
			resources:        []string{resourceOrders},
			wantSucceeded:    true,
			wantApiResources: []string{resourceOrders},
			wantApiScopes:    []string{"orders.read"},
		},
		"non isolated resources excluded by default for explicit resource": {
			clientScopes:     []string{"orders.read", "common.read"},
			scopes:           []string{"orders.read", "common.read"},
			resources:        []string{resourceOrders},
			wantSucceeded:    true,
			wantApiResources: []string{resourceOrders},
			wantApiScopes:    []string{"orders.read"},
		},
		"non isolated resources can be included for explicit resource": {
			clientScopes:       []string{"orders.read", "common.read"},
			scopes:             []string{"orders.read", "common.read"},
			resources:          []string{resourceOrders},
			includeNonIsolated: true,
			wantSucceeded:      true,
			wantApiResources:   []string{resourceCommon, resourceOrders},
			wantApiScopes:      []string{"common.read", "orders.read"},
		},
		"relative resource is invalid target": {
			clientScopes:       []string{"orders.read"},
			scopes:             []string{"orders.read"},
			resources:          []string{"orders"},
			wantInvalidTargets: []string{"orders"},
		},
		"empty resource is invalid target": {
			clientScopes:       []string{"orders.read"},
			scopes:             []string{"orders.read"},
			resources:          []string{""},
			wantInvalidTargets: []string{""},
		},
		"fragment resource is invalid target": {
			clientScopes:       []string{"orders.read"},
			scopes:             []string{"orders.read"},
			resources:          []string{resourceOrders + "#frag"},
			wantInvalidTargets: []string{resourceOrders + "#frag"},
		},
		"unknown resource is invalid target": {
			clientScopes:       []string{"orders.read"},
			scopes:             []string{"orders.read"},
			resources:          []string{"https://resources.example.com/missing"},
			wantInvalidTargets: []string{"https://resources.example.com/missing"},
		},
		"scope resource mismatch is invalid target": {
			clientScopes:       []string{"orders.read"},
			scopes:             []string{"orders.read"},
			resources:          []string{resourcePayments},
			wantInvalidTargets: []string{resourcePayments},
		},
		"scope outside client allowance is invalid scope": {
			clientScopes:      []string{"common.read"},
			scopes:            []string{"orders.read"},
			resources:         []string{resourceOrders},
			wantInvalidScopes: []string{"orders.read"},
		},
		"offline access follows client allowance": {
			clientScopes:     []string{"orders.read", gois.StandardScopesOfflineAccess},
			scopes:           []string{"orders.read", gois.StandardScopesOfflineAccess},
			resources:        []string{resourceOrders},
			wantSucceeded:    true,
			wantApiResources: []string{resourceOrders},
			wantApiScopes:    []string{"orders.read"},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			validator := NewResourceValidator(newResourceValidatorStore(t), NewScopeParser(), slog.Default())
			result, err := validator.ValidateRequestedResources(&validators_models.ResourceValidationRequest{
				Client:                         newResourceValidatorClient(tt.clientScopes),
				Scopes:                         tt.scopes,
				ResourceGaps:                   tt.resources,
				IncludeNonIsolatedApiResources: tt.includeNonIsolated,
			})
			if err != nil {
				t.Fatalf("ValidateRequestedResources error: %v", err)
			}
			if result.Succeeded() != tt.wantSucceeded {
				t.Fatalf("Succeeded() = %v, want %v; result = %#v", result.Succeeded(), tt.wantSucceeded, result)
			}
			if got := sortedStrings(result.InvalidScopes); !reflect.DeepEqual(got, sortedStrings(tt.wantInvalidScopes)) {
				t.Fatalf("InvalidScopes = %v, want %v", got, sortedStrings(tt.wantInvalidScopes))
			}
			if got := sortedStrings(result.InvalidResourceGaps); !reflect.DeepEqual(got, sortedStrings(tt.wantInvalidTargets)) {
				t.Fatalf("InvalidResourceGaps = %v, want %v", got, sortedStrings(tt.wantInvalidTargets))
			}
			if got := sortedStrings(apiResourceNames(result.Resources.ApiResources())); !reflect.DeepEqual(got, sortedStrings(tt.wantApiResources)) {
				t.Fatalf("ApiResources = %v, want %v", got, sortedStrings(tt.wantApiResources))
			}
			if got := sortedStrings(apiScopeNames(result.Resources.ApiScopes())); !reflect.DeepEqual(got, sortedStrings(tt.wantApiScopes)) {
				t.Fatalf("ApiScopes = %v, want %v", got, sortedStrings(tt.wantApiScopes))
			}
		})
	}
}

func newResourceValidatorClient(scopes []string) *storage_models.Client {
	client := storage_models.NewClient()
	client.ClientId = "client"
	client.AllowedScopes = scopes
	client.AllowOfflineAccess = containsString(scopes, gois.StandardScopesOfflineAccess)
	return client
}

func newResourceValidatorStore(t *testing.T) *memory.MemoryResourcesStore {
	t.Helper()

	ordersScope := storage_models.NewApiScope()
	ordersScope.Name = "orders.read"
	paymentsScope := storage_models.NewApiScope()
	paymentsScope.Name = "payments.read"
	commonScope := storage_models.NewApiScope()
	commonScope.Name = "common.read"

	orders := storage_models.NewApiResource()
	orders.Name = resourceOrders
	orders.Scopes = []string{ordersScope.Name}
	orders.RequireResourceGap = true
	payments := storage_models.NewApiResource()
	payments.Name = resourcePayments
	payments.Scopes = []string{paymentsScope.Name}
	payments.RequireResourceGap = true
	common := storage_models.NewApiResource()
	common.Name = resourceCommon
	common.Scopes = []string{commonScope.Name}

	store, err := memory.NewMemoryResourcesStore(nil, []*storage_models.ApiResource{orders, payments, common}, []*storage_models.ApiScope{ordersScope, paymentsScope, commonScope})
	if err != nil {
		t.Fatalf("resource store: %v", err)
	}
	return store
}

func apiResourceNames(resources []*storage_models.ApiResource) []string {
	out := make([]string, 0, len(resources))
	for _, resource := range resources {
		out = append(out, resource.Name)
	}
	return out
}

func apiScopeNames(scopes []*storage_models.ApiScope) []string {
	out := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		out = append(out, scope.Name)
	}
	return out
}

func sortedStrings(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}

func containsString(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}
