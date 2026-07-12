// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package setup

import (
	"crypto/rand"
	"crypto/rsa"
	"log/slog"
	"net/http"
	"net/http/httptest"

	"github.com/gonewx/godi"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"

	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/di"
	"github.com/gonewx/wicket/hosting"
	"github.com/gonewx/wicket/models"
	"github.com/gonewx/wicket/server"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/storage"
	storage_memory "github.com/gonewx/wicket/storage/memory"
	"github.com/gonewx/wicket/test"
	"github.com/gonewx/wicket/tokens"
)

func ConfigureServices(logger *slog.Logger) *httptest.Server {
	root, err := di.NewRoot()
	if err != nil {
		panic(err)
	}
	srv, err := server.DefaultServer(root, server.WithLogger(logger))
	if err != nil {
		panic(err)
	}

	options := godi.GetRequired[*config_options.WicketOptions](root)
	options.IssuerUri = "https://wicket-local"
	options.KeyManagement.Enabled = false

	clients := GetClients()
	identityScopes := GetIdentityScopes()
	apiResources := GetApiResources()
	apiScopes := GetApiScopes()

	userStore := test.NewTestUserStore(GetUsers())
	resourceOwnerValidator := test.NewTestUserResourceOwnerPasswordValidator(userStore, godi.GetRequired[services.SystemClock](root))
	profileProvider := func() services.ProfileService {
		return NewCustomProfileService(userStore, srv.Logger)
	}
	signingCredentialStores, validationKeysStores := developerSigningStores(jwa.RS256)

	cfg := root.ServerConfig()
	cfg.SetSigningCredentialStores(signingCredentialStores)
	cfg.SetValidationKeysStores(validationKeysStores)
	cfg.SetClients(clients)
	cfg.SetIdentityScopes(identityScopes)
	cfg.SetApiResources(apiResources)
	cfg.SetApiScopes(apiScopes)
	cfg.SetResourceOwnerValidator(resourceOwnerValidator)
	cfg.SetProfileProvider(profileProvider)
	cfg.Freeze()

	wicketMiddleware := srv.UseWicket()

	mux := http.NewServeMux()

	testServer := httptest.NewServer(hosting.ScopeMiddleware(root)(wicketMiddleware(mux)))
	testServer.Config.RegisterOnShutdown(func() {
		_ = root.Close()
	})
	return testServer
}

func developerSigningStores(signingAlgorithm jwa.SignatureAlgorithm) ([]storage.SigningCredentialStore, []storage.ValidationKeysStore) {
	raw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	credential, err := tokens.NewSigningCredentials(raw, tokens.WithAlgorithm(string(signingAlgorithm)), tokens.WithKid(thumbprintKid(raw)))
	if err != nil {
		panic(err)
	}
	keyInfo := &models.SecurityKeyInfo{
		Key:              raw.Public(),
		SigningAlgorithm: credential.Algorithm,
	}
	return []storage.SigningCredentialStore{
		storage_memory.NewMemorySigningCredentialStore(credential),
	}, []storage.ValidationKeysStore{
		storage_memory.NewMemoryValidationKeysStore([]*models.SecurityKeyInfo{keyInfo}),
	}
}

// thumbprintKid derives the RFC 7638 thumbprint key id the validation-key
// aggregation publishes, so the signed token's kid header matches the JWKS.
func thumbprintKid(raw any) string {
	key, err := jwk.FromRaw(raw)
	if err != nil {
		panic(err)
	}
	if err := jwk.AssignKeyID(key); err != nil {
		panic(err)
	}
	return key.KeyID()
}
