// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/gonewx/wicket"
	claimspkg "github.com/gonewx/wicket/claims"
	config_options "github.com/gonewx/wicket/config/options"
	responses_models "github.com/gonewx/wicket/responses/models"
	storage_models "github.com/gonewx/wicket/storage/models"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// capturingTokenCreation records the token handed to it before serialization so
// a test can observe how the token service assembled it.
type capturingTokenCreation struct {
	captured *storage_models.Token
}

func (c *capturingTokenCreation) CreateToken(ctx context.Context, token *storage_models.Token) (string, error) {
	c.captured = token
	return "serialized", nil
}

func apiResource(name string) *storage_models.ApiResource {
	resource := storage_models.NewApiResource()
	resource.Name = name
	return resource
}

func accessTokenRequest(resourceNames []string, sessionId string) *responses_models.TokenCreationRequest {
	apiResources := make([]*storage_models.ApiResource, 0, len(resourceNames))
	for _, name := range resourceNames {
		apiResources = append(apiResources, apiResource(name))
	}
	return &responses_models.TokenCreationRequest{
		ValidatedResources: validators_models.NewResourceValidationResultWithResources(
			storage_models.NewResources(storage_models.WithResourcesApiResources(apiResources)),
		),
		ValidatedRequest: &validators_models.ValidatedRequest{SessionId: sessionId},
	}
}

func claimsOfType(list []*claimspkg.Claim, claimType string) []*claimspkg.Claim {
	out := make([]*claimspkg.Claim, 0)
	for _, c := range list {
		if c.Type == claimType {
			out = append(out, c)
		}
	}
	return out
}

// TestCreateAccessTokenAudiences: the access token's audiences mirror the
// validated API resources — one audience per resource, none when no API
// resource was requested.
func TestCreateAccessTokenAudiences(t *testing.T) {
	for name, tc := range map[string]struct {
		resourceNames []string
		wantAudiences []string
	}{
		"one audience per api resource": {
			resourceNames: []string{"api-one", "api-two"},
			wantAudiences: []string{"api-one", "api-two"},
		},
		"no api resource yields no audience": {
			resourceNames: nil,
			wantAudiences: []string{},
		},
	} {
		t.Run(name, func(t *testing.T) {
			svc := NewTokenService(nil, nil, nil, fixedClock{}, nil, config_options.NewWicketOptions(), nil, nil)

			token, err := svc.CreateAccessToken(context.Background(), accessTokenRequest(tc.resourceNames, ""))

			require.NoError(t, err)
			require.ElementsMatch(t, tc.wantAudiences, token.Audiences)
		})
	}
}

// TestCreateAccessTokenSessionBinding: a session-bound request contributes a
// session-id claim carrying the session id; an anonymous request contributes
// none.
func TestCreateAccessTokenSessionBinding(t *testing.T) {
	for name, tc := range map[string]struct {
		sessionId  string
		wantSidSet bool
	}{
		"session id is emitted when present": {sessionId: "session-123", wantSidSet: true},
		"no session id emits no sid claim":   {sessionId: "", wantSidSet: false},
	} {
		t.Run(name, func(t *testing.T) {
			svc := NewTokenService(nil, nil, nil, fixedClock{}, nil, config_options.NewWicketOptions(), nil, nil)

			token, err := svc.CreateAccessToken(context.Background(), accessTokenRequest(nil, tc.sessionId))

			require.NoError(t, err)
			sidClaims := claimsOfType(token.Claims, gois.JwtClaimTypesSessionId)
			if tc.wantSidSet {
				require.Len(t, sidClaims, 1)
				require.Equal(t, tc.sessionId, sidClaims[0].Value)
			} else {
				require.Empty(t, sidClaims)
			}
		})
	}
}

// TestCreateAccessTokenSessionIdSingleClaim: a subject that already carries a
// session-id claim must not stack a second one — the token keeps exactly one
// session-id claim, the one bound to the validated request, so the claim never
// serializes as a JSON array.
func TestCreateAccessTokenSessionIdSingleClaim(t *testing.T) {
	svc := NewTokenService(nil, nil, nil, fixedClock{}, nil, config_options.NewWicketOptions(), nil, nil)

	identity := claimspkg.NewClaimsIdentity(
		claimspkg.WithAuthenticationType("test"),
		claimspkg.WithClaims([]*claimspkg.Claim{
			claimspkg.NewClaim(
				claimspkg.WithClaimType(gois.JwtClaimTypesSessionId),
				claimspkg.WithClaimValue("carried-over-session"),
			),
		}),
	)
	request := accessTokenRequest(nil, "session-123")
	request.Subject = claimspkg.NewClaimsPrincipal(claimspkg.WithClaimsPrincipalIdentity(identity))

	token, err := svc.CreateAccessToken(context.Background(), request)

	require.NoError(t, err)
	sidClaims := claimsOfType(token.Claims, gois.JwtClaimTypesSessionId)
	require.Len(t, sidClaims, 1)
	require.Equal(t, "session-123", sidClaims[0].Value)
}

// TestCreateSecurityTokenJwtIdAssembly: a jwt id is assembled only for access
// tokens whose client opted in; identity tokens never receive one, and an
// opted-in access token replaces any pre-set id with a freshly generated value.
func TestCreateSecurityTokenJwtIdAssembly(t *testing.T) {
	const presetJwtId = "carried-over-id"

	for name, tc := range map[string]struct {
		tokenType    string
		includeJwtId bool
		version      int
		presetJwtId  string
		wantJwtId    bool
	}{
		"identity without opt-in":                {tokenType: gois.TokenTypesIdentityToken, includeJwtId: false, wantJwtId: false},
		"access without opt-in":                  {tokenType: gois.TokenTypesAccessToken, includeJwtId: false, wantJwtId: false},
		"identity with opt-in":                   {tokenType: gois.TokenTypesIdentityToken, includeJwtId: true, wantJwtId: false},
		"access with opt-in":                     {tokenType: gois.TokenTypesAccessToken, includeJwtId: true, wantJwtId: true},
		"legacy-versioned access without opt-in": {tokenType: gois.TokenTypesAccessToken, includeJwtId: false, version: 1, wantJwtId: false},
		"access with opt-in replaces preset id":  {tokenType: gois.TokenTypesAccessToken, includeJwtId: true, presetJwtId: presetJwtId, wantJwtId: true},
	} {
		t.Run(name, func(t *testing.T) {
			capture := &capturingTokenCreation{}
			svc := NewTokenService(nil, nil, capture, fixedClock{}, nil, config_options.NewWicketOptions(), nil, nil)

			token := &storage_models.Token{Type: tc.tokenType, IncludeJwtId: tc.includeJwtId, Version: tc.version}
			if tc.presetJwtId != "" {
				token.Claims = append(token.Claims, claimspkg.NewClaim(
					claimspkg.WithClaimType(gois.JwtClaimTypesJwtId),
					claimspkg.WithClaimValue(tc.presetJwtId),
				))
			}

			_, err := svc.CreateSecurityToken(context.Background(), token)
			require.NoError(t, err)

			jwtIdClaims := claimsOfType(capture.captured.Claims, gois.JwtClaimTypesJwtId)
			if tc.wantJwtId {
				require.Len(t, jwtIdClaims, 1)
				require.NotEmpty(t, jwtIdClaims[0].Value)
				if tc.presetJwtId != "" {
					require.NotEqual(t, tc.presetJwtId, jwtIdClaims[0].Value)
				}
			} else {
				require.Empty(t, jwtIdClaims)
			}
		})
	}
}

// TestCreateTokenIssuerAndLifetimeAssembly: both created token kinds carry the
// validated request's issuer, the access token carries the validated access
// token lifetime, and the identity token carries the client's identity token
// lifetime — otherwise the signed JWT expires at its own issue time and names
// no issuer.
func TestCreateTokenIssuerAndLifetimeAssembly(t *testing.T) {
	client := storage_models.NewClient()
	client.IdentityTokenLifetime = 300

	request := &responses_models.TokenCreationRequest{
		ValidatedRequest: &validators_models.ValidatedRequest{
			IssuerName:          "https://issuer.wicket.test",
			AccessTokenLifetime: 3600,
			ClientId:            "relying-party",
			Client:              client,
		},
	}

	svc := NewTokenService(nil, nil, nil, fixedClock{}, nil, config_options.NewWicketOptions(), nil, nil)

	accessToken, err := svc.CreateAccessToken(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, "https://issuer.wicket.test", accessToken.Issuer)
	require.Equal(t, 3600, accessToken.Lifetime)

	identityToken, err := svc.CreateIdentityToken(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, "https://issuer.wicket.test", identityToken.Issuer)
	require.Equal(t, 300, identityToken.Lifetime)
	require.Equal(t, []string{"relying-party"}, identityToken.Audiences)
}
