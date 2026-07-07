// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/utils"
)

type Client struct {
	allowedGrantTypes []string

	Enabled                               bool
	ClientId                              string
	ProtocolType                          string
	ClientSecrets                         []*Secret
	RequireClientSecret                   bool
	ClientName                            string
	Description                           string
	ClientUri                             string
	LogoUri                               string
	RequireConsent                        bool
	AllowRememberConsent                  bool
	RequirePkce                           bool
	AllowPlainTextPkce                    bool
	RequireRequestObject                  bool
	AllowAccessTokensViaBrowser           bool
	RedirectUris                          []string
	PostLogoutRedirectUris                []string
	FrontChannelLogoutUri                 string
	FrontChannelLogoutSessionRequired     bool
	BackChannelLogoutUri                  string
	BackChannelLogoutSessionRequired      bool
	AllowOfflineAccess                    bool
	AllowedScopes                         []string
	AlwaysIncludeUserClaimsInIdToken      bool
	IdentityTokenLifetime                 int
	AllowedIdentityTokenSigningAlgorithms []string
	AccessTokenLifetime                   int
	AuthorizationCodeLifetime             int
	AbsoluteRefreshTokenLifetime          int
	SlidingRefreshTokenLifetime           int
	ConsentLifetime                       *int
	RefreshTokenUsage                     gois.TokenUsage
	UpdateAccessTokenClaimsOnRefresh      bool
	RefreshTokenExpiration                gois.TokenExpiration
	AccessTokenType                       gois.AccessTokenType
	EnableLocalLogin                      bool
	IdentityProviderRestrictions          []string
	IncludeJwtId                          bool
	Claims                                []*ClientClaim
	AlwaysSendClientClaims                bool
	ClientClaimsPrefix                    string
	PairWiseSubjectSalt                   string
	UserSsoLifetime                       int
	UserCodeType                          string
	DeviceCodeLifetime                    int
	CleanRoomGapLifetime                  *int
	PollingInterval                       *int
	CoordinateLifetimeWithUserSession     *bool
	AllowedCorsOrigins                    []string
	Properties                            map[string]string
}

func NewClient() *Client {
	return &Client{
		Enabled:                           true,
		ProtocolType:                      gois.ProtocolTypesOpenIdConnect,
		RequireClientSecret:               true,
		AllowRememberConsent:              true,
		RequirePkce:                       true,
		FrontChannelLogoutSessionRequired: true,
		BackChannelLogoutSessionRequired:  true,
		IdentityTokenLifetime:             300,
		AccessTokenLifetime:               3600,
		AuthorizationCodeLifetime:         300,
		AbsoluteRefreshTokenLifetime:      2592000,
		SlidingRefreshTokenLifetime:       1296000,
		RefreshTokenUsage:                 gois.TokenUsageOneTimeOnly,
		RefreshTokenExpiration:            gois.TokenExpirationAbsolute,
		AccessTokenType:                   gois.AccessTokenTypeJwt,
		EnableLocalLogin:                  true,
		IncludeJwtId:                      true,
		ClientClaimsPrefix:                "client_",
		DeviceCodeLifetime:                300,
	}
}

func (c *Client) AllowedGrantTypes() []string {
	return c.allowedGrantTypes
}

func (c *Client) SetAllowedGrantTypes(value []string) error {
	if err := validateGrantTypes(value); err != nil {
		return err
	}

	c.allowedGrantTypes = value
	return nil
}

func (c *Client) AddAllowedGrantTypes(value string) error {
	values := make([]string, 0)
	values = append(values, c.allowedGrantTypes...)
	values = append(values, value)

	if err := validateGrantTypes(values); err != nil {
		return err
	}
	c.allowedGrantTypes = values
	return nil
}

func validateGrantTypes(grantTypes []string) error {
	if grantTypes == nil {
		return fmt.Errorf("%s", "Argument nil for grantTypes")
	}

	for _, grantType := range grantTypes {
		if strings.Contains(grantType, " ") {
			return fmt.Errorf("%s", "Grant type cannot contain spaces")
		}
	}

	// single grant type, seems to be fine
	if len(grantTypes) == 1 {
		return nil
	}

	// don't allow duplicate grant types
	if len(grantTypes) != len(utils.Distinct(grantTypes)) {
		return fmt.Errorf("%s", "Grant types list contains duplicate values")
	}

	// would allow response_type downgrade attack from code to token
	err := disallowGrantTypeCombination(gois.GrantTypeImplicit, gois.GrantTypeAuthorizationCode, grantTypes)
	if err != nil {
		return err
	}

	err = disallowGrantTypeCombination(gois.GrantTypeImplicit, gois.GrantTypeHybrid, grantTypes)
	if err != nil {
		return err
	}

	err = disallowGrantTypeCombination(gois.GrantTypeAuthorizationCode, gois.GrantTypeHybrid, grantTypes)
	if err != nil {
		return err
	}

	return nil
}

func disallowGrantTypeCombination(value1, value2 string, grantTypes []string) error {
	if utils.Contains(grantTypes, value1) && utils.Contains(grantTypes, value2) {
		return fmt.Errorf("Grant types list cannot contain both %s and %s", value1, value2)
	}
	return nil
}

func (c *Client) GetKeys() jwk.Set {
	set := jwk.NewSet()
	secrets := utils.Where(c.ClientSecrets, func(secret *Secret) bool {
		return secret.Type == gois.SecretTypesX509CertificateBase64
	})
	keys := utils.Select(secrets, func(s *Secret) jwk.Key {
		data, err := base64.StdEncoding.DecodeString(s.Value)
		if err != nil {
			return nil
		}

		key, err := jwk.ParseKey(data)
		if err != nil {
			return nil
		}
		return key
	})

	for _, key := range keys {
		if key != nil {
			if err := set.AddKey(key); err != nil {
				continue
			}
		}
	}

	secrets = utils.Where(c.ClientSecrets, func(secret *Secret) bool {
		return secret.Type == gois.SecretTypesJsonWebKey
	})
	keys = utils.Select(secrets, func(s *Secret) jwk.Key {
		key, err := jwk.ParseKey([]byte(s.Value))
		if err != nil {
			return nil
		}
		return key
	})
	for _, key := range keys {
		if key != nil {
			if err := set.AddKey(key); err != nil {
				continue
			}
		}
	}
	return set
}

// IsImplicitOnly Returns true if the client is an implicit-only client.
func (c *Client) IsImplicitOnly() bool {
	return c != nil &&
		c.AllowedGrantTypes() != nil &&
		len(c.AllowedGrantTypes()) == 1 &&
		c.AllowedGrantTypes()[0] == gois.GrantTypeImplicit
}
