// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package setup

import (
	"encoding/base64"

	"github.com/gonewx/wicket"
	storage_models "github.com/gonewx/wicket/storage/models"
	integration_common "github.com/gonewx/wicket/test/integration/common"
	"github.com/gonewx/wicket/utils"
)

func GetClients() []*storage_models.Client {
	// Console Client Credentials Flow Sample
	client := storage_models.NewClient()
	client.ClientId = "client"

	secret := storage_models.NewSecret()
	secret.Value = utils.Sha256("secret")
	client.ClientSecrets = []*storage_models.Secret{secret}

	if err := client.SetAllowedGrantTypes(gois.GrantTypesClientCredentials); err != nil {
		panic(err)
	}

	client.AllowOfflineAccess = true

	client.AllowedScopes = []string{
		"api1", "api2", "other_api",
	}

	clientCnf := storage_models.NewClient()
	clientCnf.ClientId = "client.cnf"

	secret = storage_models.NewSecret()
	secret.Type = "confirmation.test"
	secret.Description = "Test for cnf claim"
	secret.Value = "foo"
	clientCnf.ClientSecrets = []*storage_models.Secret{secret}

	if err := clientCnf.SetAllowedGrantTypes(gois.GrantTypesClientCredentials); err != nil {
		panic(err)
	}

	clientCnf.AllowOfflineAccess = true

	clientCnf.AllowedScopes = []string{
		"api1", "api2",
	}

	clientAndRo := storage_models.NewClient()
	clientAndRo.ClientId = "client.and.ro"

	secret = storage_models.NewSecret()
	secret.Value = utils.Sha256("secret")
	clientAndRo.ClientSecrets = []*storage_models.Secret{secret}

	if err := clientAndRo.SetAllowedGrantTypes(gois.GrantTypesResourceOwnerPasswordAndClientCredentials); err != nil {
		panic(err)
	}

	clientAndRo.AllowedScopes = []string{
		"openid", "api1", "api2",
	}

	clientIdentityscopes := storage_models.NewClient()
	clientIdentityscopes.ClientId = "client.identityscopes"

	secret = storage_models.NewSecret()
	secret.Value = utils.Sha256("secret")
	clientIdentityscopes.ClientSecrets = []*storage_models.Secret{secret}

	if err := clientIdentityscopes.SetAllowedGrantTypes(gois.GrantTypesClientCredentials); err != nil {
		panic(err)
	}

	clientIdentityscopes.AllowedScopes = []string{
		"openid", "profile", "api1", "api2",
	}

	clientNoDefaultScopes := storage_models.NewClient()
	clientNoDefaultScopes.ClientId = "client.no_default_scopes"

	secret = storage_models.NewSecret()
	secret.Value = utils.Sha256("secret")
	clientNoDefaultScopes.ClientSecrets = []*storage_models.Secret{secret}

	if err := clientNoDefaultScopes.SetAllowedGrantTypes(gois.GrantTypesClientCredentials); err != nil {
		panic(err)
	}

	clientNoSecret := storage_models.NewClient()
	clientNoSecret.ClientId = "client.no_secret"
	if err := clientNoSecret.SetAllowedGrantTypes(gois.GrantTypesClientCredentials); err != nil {
		panic(err)
	}
	clientNoSecret.RequireClientSecret = false
	clientNoSecret.AllowedScopes = []string{
		"api1",
	}

	// Console Resource Owner Flow Sample
	roclient := storage_models.NewClient()
	roclient.ClientId = "roclient"

	secret = storage_models.NewSecret()
	secret.Value = utils.Sha256("secret")
	roclient.ClientSecrets = []*storage_models.Secret{secret}

	if err := roclient.SetAllowedGrantTypes(gois.GrantTypesPassword); err != nil {
		panic(err)
	}
	roclient.RefreshTokenUsage = gois.TokenUsageOneTimeOnly
	roclient.AllowOfflineAccess = true
	roclient.AllowedScopes = []string{
		gois.StandardScopesOpenId,
		gois.StandardScopesEmail,
		gois.StandardScopesAddress,
		"roles",
		"api1", "api2", "api4.with.roles",
	}

	roclientReuse := storage_models.NewClient()
	roclientReuse.ClientId = "roclient.reuse"

	secret = storage_models.NewSecret()
	secret.Value = utils.Sha256("secret")
	roclientReuse.ClientSecrets = []*storage_models.Secret{secret}

	if err := roclientReuse.SetAllowedGrantTypes(gois.GrantTypesPassword); err != nil {
		panic(err)
	}
	roclientReuse.AllowOfflineAccess = true
	roclientReuse.AllowedScopes = []string{
		gois.StandardScopesOpenId,
		gois.StandardScopesEmail,
		gois.StandardScopesAddress,
		"roles",
		"api1", "api2", "api4.with.roles",
	}
	roclientReuse.RefreshTokenUsage = gois.TokenUsageReUse

	// Console Custom Grant Flow Sample
	clientCustom := storage_models.NewClient()
	clientCustom.ClientId = "client.custom"

	secret = storage_models.NewSecret()
	secret.Value = utils.Sha256("secret")
	clientCustom.ClientSecrets = []*storage_models.Secret{secret}

	if err := clientCustom.SetAllowedGrantTypes([]string{"custom", "custom.nosubject"}); err != nil {
		panic(err)
	}

	clientCustom.AllowedScopes = []string{
		"api1", "api2",
	}
	clientCustom.AllowOfflineAccess = true

	clientDynamic := storage_models.NewClient()
	clientDynamic.ClientId = "client.dynamic"

	secret = storage_models.NewSecret()
	secret.Value = utils.Sha256("secret")
	clientDynamic.ClientSecrets = []*storage_models.Secret{secret}

	if err := clientDynamic.SetAllowedGrantTypes([]string{"dynamic"}); err != nil {
		panic(err)
	}

	clientDynamic.AllowedScopes = []string{
		"api1", "api2",
	}
	clientDynamic.AlwaysSendClientClaims = true

	// Introspection Client Sample
	roclientReference := storage_models.NewClient()
	roclientReference.ClientId = "roclient.reference"

	secret = storage_models.NewSecret()
	secret.Value = utils.Sha256("secret")
	roclientReference.ClientSecrets = []*storage_models.Secret{secret}

	if err := roclientReference.SetAllowedGrantTypes(gois.GrantTypesPassword); err != nil {
		panic(err)
	}

	roclientReference.AllowOfflineAccess = true
	roclientReference.AllowedScopes = []string{
		"api1", "api2",
	}
	roclientReference.AccessTokenType = gois.AccessTokenTypeReference

	certificateBase64Valid := storage_models.NewClient()
	certificateBase64Valid.ClientName = "Client with Base64 encoded X509 Certificate"
	certificateBase64Valid.ClientId = "certificate_base64_valid"
	certificateBase64Valid.Enabled = true

	testcert, err := integration_common.NewTestCert().Load()
	if err != nil {
		panic(err)
	}

	secret = storage_models.NewSecret()
	secret.Type = gois.SecretTypesX509CertificateBase64
	secret.Value = base64.StdEncoding.EncodeToString(testcert)
	certificateBase64Valid.ClientSecrets = []*storage_models.Secret{secret}

	if err := certificateBase64Valid.SetAllowedGrantTypes(gois.GrantTypesClientCredentials); err != nil {
		panic(err)
	}

	certificateBase64Valid.AllowedScopes = []string{
		"api1", "api2",
	}

	implicit := storage_models.NewClient()
	implicit.ClientId = "implicit"
	if err := implicit.SetAllowedGrantTypes(gois.GrantTypesImplicit); err != nil {
		panic(err)
	}

	implicit.AllowedScopes = []string{
		"api1",
	}
	implicit.RedirectUris = []string{
		"http://implicit",
	}

	implicitAndClientCreds := storage_models.NewClient()
	implicitAndClientCreds.ClientId = "implicit_and_client_creds"
	if err := implicitAndClientCreds.SetAllowedGrantTypes(gois.GrantTypesImplicitAndClientCredentials); err != nil {
		panic(err)
	}

	implicitAndClientCreds.AllowedScopes = []string{
		"api1",
	}
	implicitAndClientCreds.RedirectUris = []string{
		"http://implicit_and_client_creds",
	}

	return []*storage_models.Client{
		client,
		clientCnf,
		clientAndRo,
		clientIdentityscopes,
		clientNoDefaultScopes,
		clientNoSecret,
		roclient,
		roclientReuse,
		clientCustom,
		clientDynamic,
		roclientReference,
		certificateBase64Valid,
		implicit,
		implicitAndClientCreds,
	}
}
