// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package mock

import (
	"github.com/gonewx/wicket"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/utils"
)

type TestClients struct{}

func (c TestClients) Get() []*storage_models.Client {
	client := storage_models.NewClient()
	client.ClientName = "Code Client"
	client.Enabled = true
	client.ClientId = "codeclient"

	secret := storage_models.NewSecret()
	secret.Value = utils.Sha256("secret")

	client.ClientSecrets = []*storage_models.Secret{secret}
	if err := client.SetAllowedGrantTypes(gois.GrantTypesCode); err != nil {
		panic(err)
	}

	client.AllowOfflineAccess = true
	client.AllowedScopes = []string{"openid", "profile", "resource", "resource2", "scope1"}
	client.RequireConsent = false
	client.RequirePkce = false
	client.RedirectUris = []string{"https://server/cb"}
	client.AuthorizationCodeLifetime = 60

	clientAllowPlainTextPkce := storage_models.NewClient()
	clientAllowPlainTextPkce.ClientName = "Code Client (allows plain text PKCE)"
	clientAllowPlainTextPkce.Enabled = true
	clientAllowPlainTextPkce.ClientId = "codeclient.plain"

	secret = storage_models.NewSecret()
	secret.Value = utils.Sha256("secret")

	clientAllowPlainTextPkce.ClientSecrets = []*storage_models.Secret{secret}
	clientAllowPlainTextPkce.AllowedScopes = []string{"openid", "profile", "resource", "resource2"}
	clientAllowPlainTextPkce.AllowPlainTextPkce = true
	clientAllowPlainTextPkce.RequireConsent = false
	clientAllowPlainTextPkce.RedirectUris = []string{"https://server/cb"}
	if err := clientAllowPlainTextPkce.SetAllowedGrantTypes(gois.GrantTypesCode); err != nil {
		panic(err)
	}
	clientWithPkce := storage_models.NewClient()
	clientWithPkce.ClientName = "Code Client with PKCE"
	clientWithPkce.Enabled = true
	clientWithPkce.ClientId = "codeclient.pkce"

	secret = storage_models.NewSecret()
	secret.Value = utils.Sha256("secret")

	clientWithPkce.ClientSecrets = []*storage_models.Secret{secret}
	clientWithPkce.AllowedScopes = []string{"openid", "profile", "resource", "resource2"}
	clientWithPkce.RequireConsent = false
	clientWithPkce.RequirePkce = true
	clientWithPkce.RedirectUris = []string{"https://server/cb"}
	clientWithPkce.AuthorizationCodeLifetime = 60
	if err := clientWithPkce.SetAllowedGrantTypes(gois.GrantTypesCode); err != nil {
		panic(err)
	}

	clientWithPkcePlainAllowed := storage_models.NewClient()
	clientWithPkcePlainAllowed.ClientName = "Code Client with PKCE and plain allowed"
	clientWithPkcePlainAllowed.Enabled = true
	clientWithPkcePlainAllowed.ClientId = "codeclient.pkce.plain"

	secret = storage_models.NewSecret()
	secret.Value = utils.Sha256("secret")

	clientWithPkcePlainAllowed.ClientSecrets = []*storage_models.Secret{secret}
	if err := clientWithPkcePlainAllowed.SetAllowedGrantTypes(gois.GrantTypesCode); err != nil {
		panic(err)
	}
	clientWithPkcePlainAllowed.RequirePkce = true
	clientWithPkcePlainAllowed.AllowPlainTextPkce = true
	clientWithPkcePlainAllowed.AllowedScopes = []string{"openid", "profile", "resource", "resource2"}
	clientWithPkcePlainAllowed.RequireConsent = false
	clientWithPkcePlainAllowed.RedirectUris = []string{"https://server/cb"}
	clientWithPkcePlainAllowed.AuthorizationCodeLifetime = 60

	clientHybrid := storage_models.NewClient()
	clientHybrid.ClientName = "Hybrid Client"
	clientHybrid.Enabled = true
	clientHybrid.ClientId = "hybridclient"

	secret = storage_models.NewSecret()
	secret.Value = utils.Sha256("secret")

	clientHybrid.ClientSecrets = []*storage_models.Secret{secret}
	if err := clientHybrid.SetAllowedGrantTypes(gois.GrantTypesHybrid); err != nil {
		panic(err)
	}
	clientHybrid.AllowedScopes = []string{"openid", "profile", "resource", "resource2"}
	clientHybrid.AllowAccessTokensViaBrowser = true
	clientHybrid.RequireConsent = false
	clientHybrid.RequirePkce = false
	clientHybrid.RedirectUris = []string{"https://server/cb"}
	clientHybrid.AuthorizationCodeLifetime = 60

	clientHybridWithPkce := storage_models.NewClient()
	clientHybridWithPkce.ClientName = "Hybrid Client with PKCE"
	clientHybridWithPkce.Enabled = true
	clientHybridWithPkce.ClientId = "hybridclient.pkce"

	secret = storage_models.NewSecret()
	secret.Value = utils.Sha256("secret")

	clientHybridWithPkce.ClientSecrets = []*storage_models.Secret{secret}
	if err := clientHybridWithPkce.SetAllowedGrantTypes(gois.GrantTypesHybrid); err != nil {
		panic(err)
	}
	clientHybridWithPkce.RequirePkce = true
	clientHybridWithPkce.AllowedScopes = []string{"openid", "profile", "resource", "resource2"}
	clientHybridWithPkce.AllowAccessTokensViaBrowser = true
	clientHybridWithPkce.RequireConsent = false
	clientHybridWithPkce.RedirectUris = []string{"https://server/cb"}
	clientHybridWithPkce.AuthorizationCodeLifetime = 60

	clientHybridNoAavb := storage_models.NewClient()
	clientHybridNoAavb.ClientName = "Hybrid Client"
	clientHybridNoAavb.Enabled = true
	clientHybridNoAavb.ClientId = "hybridclient_no_aavb"

	secret = storage_models.NewSecret()
	secret.Value = utils.Sha256("secret")

	clientHybridNoAavb.ClientSecrets = []*storage_models.Secret{secret}
	if err := clientHybridNoAavb.SetAllowedGrantTypes(gois.GrantTypesHybrid); err != nil {
		panic(err)
	}
	clientHybridNoAavb.AllowedScopes = []string{"openid", "profile", "resource", "resource2"}
	clientHybridNoAavb.AllowAccessTokensViaBrowser = false
	clientHybridNoAavb.RequireConsent = false
	clientHybridNoAavb.RequirePkce = false
	clientHybridNoAavb.RedirectUris = []string{"https://server/cb"}
	clientHybridNoAavb.AuthorizationCodeLifetime = 60

	clientImplicit := storage_models.NewClient()
	clientImplicit.ClientName = "Implicit Client"
	clientImplicit.ClientId = "implicitclient"
	if err := clientImplicit.SetAllowedGrantTypes(gois.GrantTypesImplicit); err != nil {
		panic(err)
	}
	clientImplicit.AllowedScopes = []string{"openid", "profile", "resource", "resource2"}
	clientImplicit.AllowAccessTokensViaBrowser = true
	clientImplicit.RequireConsent = false
	clientImplicit.RedirectUris = []string{"oob://implicit/cb"}

	clientImplicitNoAavb := storage_models.NewClient()
	clientImplicitNoAavb.ClientName = "Implicit Client"
	clientImplicitNoAavb.ClientId = "implicitclient_no_aavb"
	if err := clientImplicitNoAavb.SetAllowedGrantTypes(gois.GrantTypesImplicit); err != nil {
		panic(err)
	}
	clientImplicitNoAavb.AllowedScopes = []string{"openid", "profile", "resource", "resource2"}
	clientImplicitNoAavb.AllowAccessTokensViaBrowser = false
	clientImplicitNoAavb.RequireConsent = false
	clientImplicitNoAavb.RedirectUris = []string{"oob://implicit/cb"}

	clientImplicitCreds := storage_models.NewClient()
	clientImplicitCreds.ClientName = "Implicit and Client Credentials Client"
	clientImplicitCreds.Enabled = true
	clientImplicitCreds.ClientId = "implicit_and_client_creds_client"

	secret = storage_models.NewSecret()
	secret.Value = utils.Sha256("secret")

	clientImplicitCreds.ClientSecrets = []*storage_models.Secret{secret}
	if err := clientImplicitCreds.SetAllowedGrantTypes(gois.GrantTypesImplicitAndClientCredentials); err != nil {
		panic(err)
	}
	clientImplicitCreds.AllowedScopes = []string{"openid", "profile", "resource", "resource2"}
	clientImplicitCreds.RequireConsent = false
	clientImplicitCreds.RedirectUris = []string{"oob://implicit/cb"}

	clientScopeRestrictions := storage_models.NewClient()
	clientScopeRestrictions.ClientName = "Code Client with Scope Restrictions"
	clientScopeRestrictions.Enabled = true
	clientScopeRestrictions.ClientId = "codeclient_restricted"

	secret = storage_models.NewSecret()
	secret.Value = utils.Sha256("secret")

	clientScopeRestrictions.ClientSecrets = []*storage_models.Secret{secret}
	if err := clientScopeRestrictions.SetAllowedGrantTypes(gois.GrantTypesCode); err != nil {
		panic(err)
	}
	clientScopeRestrictions.RequireConsent = false
	clientScopeRestrictions.RequirePkce = false
	clientScopeRestrictions.AllowOfflineAccess = true
	clientScopeRestrictions.AllowedScopes = []string{"openid"}
	clientScopeRestrictions.RedirectUris = []string{"https://server/cb"}

	clientCredentials := storage_models.NewClient()
	clientCredentials.ClientName = "Client Credentials Client"
	clientCredentials.Enabled = true
	clientCredentials.ClientId = "client"

	secret = storage_models.NewSecret()
	secret.Value = utils.Sha256("secret")

	clientCredentials.ClientSecrets = []*storage_models.Secret{secret}
	if err := clientCredentials.SetAllowedGrantTypes(gois.GrantTypesClientCredentials); err != nil {
		panic(err)
	}
	clientCredentials.AllowedScopes = []string{"openid", "profile", "resource", "resource2", "scope1"}
	clientCredentials.AllowOfflineAccess = true
	clientCredentials.AccessTokenType = gois.AccessTokenTypeJwt

	clientCredentialsRestricted := storage_models.NewClient()
	clientCredentialsRestricted.ClientName = "Client Credentials Client (restricted)"
	clientCredentialsRestricted.Enabled = true
	clientCredentialsRestricted.ClientId = "client_restricted"

	secret = storage_models.NewSecret()
	secret.Value = utils.Sha256("secret")

	clientCredentialsRestricted.ClientSecrets = []*storage_models.Secret{secret}
	if err := clientCredentialsRestricted.SetAllowedGrantTypes(gois.GrantTypesClientCredentials); err != nil {
		panic(err)
	}
	clientCredentialsRestricted.AllowedScopes = []string{"resource"}

	clientResourceOwner := storage_models.NewClient()
	clientResourceOwner.ClientName = "Resource Owner Client"
	clientResourceOwner.Enabled = true
	clientResourceOwner.ClientId = "roclient"

	secret = storage_models.NewSecret()
	secret.Value = utils.Sha256("secret")

	clientResourceOwner.ClientSecrets = []*storage_models.Secret{secret}
	if err := clientResourceOwner.SetAllowedGrantTypes(gois.GrantTypesPassword); err != nil {
		panic(err)
	}
	clientResourceOwner.AllowedScopes = []string{"openid", "profile", "resource", "resource2", "scope1"}
	clientResourceOwner.AllowOfflineAccess = true

	clientResourceOwnerPublic := storage_models.NewClient()
	clientResourceOwnerPublic.ClientName = "Resource Owner Client  - Public"
	clientResourceOwnerPublic.Enabled = true
	clientResourceOwnerPublic.ClientId = "roclient.public"
	clientResourceOwnerPublic.RequireClientSecret = false
	if err := clientResourceOwnerPublic.SetAllowedGrantTypes(gois.GrantTypesPassword); err != nil {
		panic(err)
	}
	clientResourceOwnerPublic.AllowedScopes = []string{"openid", "profile", "resource", "resource2"}

	clientResourceOwnerRefresh := storage_models.NewClient()
	clientResourceOwnerRefresh.ClientName = "Resource Owner Client"
	clientResourceOwnerRefresh.Enabled = true
	clientResourceOwnerRefresh.ClientId = "roclient_absolute_refresh_expiration_one_time_only"

	secret = storage_models.NewSecret()
	secret.Value = utils.Sha256("secret")

	clientResourceOwnerRefresh.ClientSecrets = []*storage_models.Secret{secret}
	if err := clientResourceOwnerRefresh.SetAllowedGrantTypes(gois.GrantTypesPassword); err != nil {
		panic(err)
	}
	clientResourceOwnerRefresh.AllowedScopes = []string{"openid", "profile", "resource", "resource2", "scope1"}
	clientResourceOwnerRefresh.RefreshTokenExpiration = gois.TokenExpirationAbsolute
	clientResourceOwnerRefresh.RefreshTokenUsage = gois.TokenUsageOneTimeOnly
	clientResourceOwnerRefresh.AbsoluteRefreshTokenLifetime = 200

	clientResourceOwnerRefreshReuse := storage_models.NewClient()
	clientResourceOwnerRefreshReuse.ClientName = "Resource Owner Client"
	clientResourceOwnerRefreshReuse.Enabled = true
	clientResourceOwnerRefreshReuse.ClientId = "roclient_absolute_refresh_expiration_reuse"

	secret = storage_models.NewSecret()
	secret.Value = utils.Sha256("secret")

	clientResourceOwnerRefreshReuse.ClientSecrets = []*storage_models.Secret{secret}
	if err := clientResourceOwnerRefreshReuse.SetAllowedGrantTypes(gois.GrantTypesPassword); err != nil {
		panic(err)
	}
	clientResourceOwnerRefreshReuse.AllowedScopes = []string{"openid", "profile", "resource", "resource2", "scope1"}
	clientResourceOwnerRefreshReuse.RefreshTokenExpiration = gois.TokenExpirationAbsolute
	clientResourceOwnerRefreshReuse.RefreshTokenUsage = gois.TokenUsageReUse
	clientResourceOwnerRefreshReuse.AbsoluteRefreshTokenLifetime = 200

	clientResourceOwnerSlidingRefresh := storage_models.NewClient()
	clientResourceOwnerSlidingRefresh.ClientName = "Resource Owner Client"
	clientResourceOwnerSlidingRefresh.Enabled = true
	clientResourceOwnerSlidingRefresh.ClientId = "roclient_sliding_refresh_expiration_one_time_only"

	secret = storage_models.NewSecret()
	secret.Value = utils.Sha256("secret")

	clientResourceOwnerSlidingRefresh.ClientSecrets = []*storage_models.Secret{secret}
	if err := clientResourceOwnerSlidingRefresh.SetAllowedGrantTypes(gois.GrantTypesPassword); err != nil {
		panic(err)
	}
	clientResourceOwnerSlidingRefresh.AllowedScopes = []string{"openid", "profile", "resource", "resource2", "scope1"}
	clientResourceOwnerSlidingRefresh.RefreshTokenExpiration = gois.TokenExpirationSliding
	clientResourceOwnerSlidingRefresh.RefreshTokenUsage = gois.TokenUsageOneTimeOnly
	clientResourceOwnerSlidingRefresh.AbsoluteRefreshTokenLifetime = 10
	clientResourceOwnerSlidingRefresh.SlidingRefreshTokenLifetime = 4

	clientResourceOwnerSlidingRefreshReuse := storage_models.NewClient()
	clientResourceOwnerSlidingRefreshReuse.ClientName = "Resource Owner Client"
	clientResourceOwnerSlidingRefreshReuse.Enabled = true
	clientResourceOwnerSlidingRefreshReuse.ClientId = "roclient_sliding_refresh_expiration_reuse"

	secret = storage_models.NewSecret()
	secret.Value = utils.Sha256("secret")

	clientResourceOwnerSlidingRefreshReuse.ClientSecrets = []*storage_models.Secret{secret}
	if err := clientResourceOwnerSlidingRefreshReuse.SetAllowedGrantTypes(gois.GrantTypesPassword); err != nil {
		panic(err)
	}
	clientResourceOwnerSlidingRefreshReuse.AllowedScopes = []string{"openid", "profile", "resource", "resource2", "scope1"}
	clientResourceOwnerSlidingRefreshReuse.RefreshTokenExpiration = gois.TokenExpirationSliding
	clientResourceOwnerSlidingRefreshReuse.RefreshTokenUsage = gois.TokenUsageReUse
	clientResourceOwnerSlidingRefreshReuse.AbsoluteRefreshTokenLifetime = 200
	clientResourceOwnerSlidingRefreshReuse.SlidingRefreshTokenLifetime = 100

	clientResourceOwnerRestricted := storage_models.NewClient()
	clientResourceOwnerRestricted.ClientName = "Resource Owner Client  (restricted)"
	clientResourceOwnerRestricted.Enabled = true
	clientResourceOwnerRestricted.ClientId = "roclient_restricted"

	secret = storage_models.NewSecret()
	secret.Value = utils.Sha256("secret")

	clientResourceOwnerRestricted.ClientSecrets = []*storage_models.Secret{secret}
	if err := clientResourceOwnerRestricted.SetAllowedGrantTypes(gois.GrantTypesPassword); err != nil {
		panic(err)
	}
	clientResourceOwnerRestricted.AllowedScopes = []string{"resource"}

	clientResourceOwnerRestrictedRefresh := storage_models.NewClient()
	clientResourceOwnerRestrictedRefresh.ClientName = "Resource Owner Client  (restricted with refresh)"
	clientResourceOwnerRestrictedRefresh.Enabled = true
	clientResourceOwnerRestrictedRefresh.ClientId = "roclient_restricted_refresh"

	secret = storage_models.NewSecret()
	secret.Value = utils.Sha256("secret")

	clientResourceOwnerRestrictedRefresh.ClientSecrets = []*storage_models.Secret{secret}
	if err := clientResourceOwnerRestrictedRefresh.SetAllowedGrantTypes(gois.GrantTypesPassword); err != nil {
		panic(err)
	}
	clientResourceOwnerRestrictedRefresh.AllowOfflineAccess = true
	clientResourceOwnerRestrictedRefresh.AllowedScopes = []string{"resource"}

	clientCustom := storage_models.NewClient()
	clientCustom.ClientName = "Custom Grant Client"
	clientCustom.Enabled = true
	clientCustom.ClientId = "customgrantclient"

	secret = storage_models.NewSecret()
	secret.Value = utils.Sha256("secret")

	clientCustom.ClientSecrets = []*storage_models.Secret{secret}
	if err := clientCustom.SetAllowedGrantTypes([]string{"custom_grant"}); err != nil {
		panic(err)
	}
	clientCustom.AllowedScopes = []string{"openid", "profile", "resource", "resource2"}

	clientDisabled := storage_models.NewClient()
	clientDisabled.ClientName = "Disabled Client"
	clientDisabled.Enabled = false
	clientDisabled.ClientId = "disabled"
	clientDisabled.ClientSecrets = []*storage_models.Secret{{Value: utils.Sha256("invalid")}}
	if err := clientDisabled.SetAllowedGrantTypes(gois.GrantTypesClientCredentials); err != nil {
		panic(err)
	}
	clientDisabled.AllowedScopes = []string{"openid", "profile", "resource", "resource2"}

	clientReference := storage_models.NewClient()
	clientReference.ClientName = "Reference Token Client"
	clientReference.Enabled = true
	clientReference.ClientId = "referencetokenclient"

	secret = storage_models.NewSecret()
	secret.Value = utils.Sha256("secret")

	clientReference.ClientSecrets = []*storage_models.Secret{secret}
	if err := clientReference.SetAllowedGrantTypes(gois.GrantTypesImplicit); err != nil {
		panic(err)
	}
	clientReference.RedirectUris = []string{"https://notused"}
	clientReference.AllowedScopes = []string{"openid", "profile", "resource", "resource2"}
	clientReference.AccessTokenType = gois.AccessTokenTypeReference

	clientWSFed := storage_models.NewClient()
	clientWSFed.ClientName = "WS-Fed Client"
	clientWSFed.Enabled = true
	clientWSFed.ClientId = "saml2p-gap"
	clientWSFed.ProtocolType = gois.ProtocolTypesSaml2p
	if err := clientWSFed.SetAllowedGrantTypes(gois.GrantTypesImplicit); err != nil {
		panic(err)
	}
	clientWSFed.AllowedScopes = []string{"openid", "profile", "resource", "resource2"}
	clientWSFed.RedirectUris = []string{"http://saml2p-gap/callback"}

	clientCredWSFed := storage_models.NewClient()
	clientCredWSFed.ClientName = "WS-Fed Client"
	clientCredWSFed.Enabled = true
	clientCredWSFed.ClientId = "client.cred.saml2p-gap"
	clientCredWSFed.ProtocolType = gois.ProtocolTypesSaml2p
	if err := clientCredWSFed.SetAllowedGrantTypes(gois.GrantTypesClientCredentials); err != nil {
		panic(err)
	}
	clientCredWSFed.AllowedScopes = []string{"openid", "profile", "resource", "resource2"}

	clientImplicitNotUsed := storage_models.NewClient()
	clientImplicitNotUsed.ClientName = "Implicit Client"
	clientImplicitNotUsed.Enabled = true
	clientImplicitNotUsed.ClientId = "client.implicit"
	if err := clientImplicitNotUsed.SetAllowedGrantTypes(gois.GrantTypesImplicit); err != nil {
		panic(err)
	}
	clientImplicitNotUsed.RedirectUris = []string{"https://notused"}
	clientImplicitNotUsed.AllowedScopes = []string{"openid", "profile", "resource", "resource2"}

	clientImplicitNotUsedCreds := storage_models.NewClient()
	clientImplicitNotUsedCreds.ClientId = "implicit_and_client_creds"
	if err := clientImplicitNotUsedCreds.SetAllowedGrantTypes(gois.GrantTypesImplicitAndClientCredentials); err != nil {
		panic(err)
	}
	clientImplicitNotUsedCreds.RedirectUris = []string{"https://notused"}
	clientImplicitNotUsedCreds.AllowedScopes = []string{"api1"}

	clientDeviceFlow := storage_models.NewClient()
	clientDeviceFlow.ClientName = "Device Flow Client"
	clientDeviceFlow.ClientId = "device_flow"
	if err := clientDeviceFlow.SetAllowedGrantTypes(gois.GrantTypesDeviceFlow); err != nil {
		panic(err)
	}
	clientDeviceFlow.AllowedScopes = []string{"openid", "profile", "resource"}
	clientDeviceFlow.AllowOfflineAccess = true

	secret = storage_models.NewSecret()
	secret.Value = utils.Sha256("secret")

	clientDeviceFlow.ClientSecrets = []*storage_models.Secret{secret}

	return []*storage_models.Client{
		client,
		clientAllowPlainTextPkce,
		clientWithPkce,
		clientWithPkcePlainAllowed,
		clientHybrid,
		clientHybridWithPkce,
		clientHybridNoAavb,
		clientImplicit,
		clientImplicitNoAavb,
		clientImplicitCreds,
		clientScopeRestrictions,
		clientCredentials,
		clientCredentialsRestricted,
		clientResourceOwner,
		clientResourceOwnerPublic,
		clientResourceOwnerRefresh,
		clientResourceOwnerRefreshReuse,
		clientResourceOwnerSlidingRefresh,
		clientResourceOwnerSlidingRefreshReuse,
		clientResourceOwnerRestricted,
		clientResourceOwnerRestrictedRefresh,
		clientCustom,
		clientDisabled,
		clientReference,
		clientWSFed,
		clientCredWSFed,
		clientImplicitNotUsed,
		clientImplicitNotUsedCreds,
		clientDeviceFlow,
	}
}
