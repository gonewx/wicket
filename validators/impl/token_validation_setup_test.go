// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gonewx/wicket"
	claimspkg "github.com/gonewx/wicket/claims"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/dp"
	"github.com/gonewx/wicket/keymgmt"
	"github.com/gonewx/wicket/services"
	services_impl "github.com/gonewx/wicket/services/impl"
	"github.com/gonewx/wicket/storage"
	storage_impl "github.com/gonewx/wicket/storage/impl"
	storage_models "github.com/gonewx/wicket/storage/models"
	test_common "github.com/gonewx/wicket/test/common"
	validators_mock "github.com/gonewx/wicket/validators/mock"
)

// tokenTestNow is the fixed reference instant injected into token validation
// tests so reference-token lifetime arithmetic never depends on the real wall
// clock.
var tokenTestNow = time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)

// tokenTestIssuer is the issuer shared by the signing helpers and the validator
// so the issuer claim round-trips through JWT validation.
const tokenTestIssuer = "https://issuer.wicket.test"

// createReferenceTokenStore builds an empty in-memory reference token store.
func createReferenceTokenStore() *storage_impl.ReferenceTokenStore {
	return storage_impl.NewReferenceTokenStore()
}

// --- shared signing material ---------------------------------------------
//
// JWT round-trip tests need the signing side and the validation side to agree
// on key material: the header key id a token advertises must resolve against
// the published key set. Both sides therefore share one key manager, whose
// RFC 7638 thumbprint key id is exactly what the validation side re-derives.

type reversibleKeyProvider struct{}

func (reversibleKeyProvider) Create(string) dp.DataProtector { return reversibleKeyProtector{} }

type reversibleKeyProtector struct{}

func (p reversibleKeyProtector) Create(string) dp.DataProtector { return p }

func (reversibleKeyProtector) Protect(data []byte) []byte { return append([]byte("p:"), data...) }
func (reversibleKeyProtector) Unprotect(data []byte) ([]byte, error) {
	if len(data) < 2 {
		return nil, errors.New("corrupt protected payload")
	}
	return data[2:], nil
}

type keyManagerClock struct{}

func (keyManagerClock) Now() time.Time { return time.Date(2026, 7, 9, 0, 0, 0, 0, time.UTC) }

var (
	sharedKeyMaterialOnce sync.Once
	sharedKeyMaterialSvc  *services_impl.KeyMaterialService
)

// sharedKeyMaterial returns a process-wide key material service backed by an
// auto-managed RS256 key. Signing and validation both flow through it so a
// signed token's header key id always resolves through the validation key set.
func sharedKeyMaterial() *services_impl.KeyMaterialService {
	sharedKeyMaterialOnce.Do(func() {
		manager := keymgmt.NewManager(keymgmt.Config{
			Enabled:            true,
			AutoCreate:         true,
			RotationInterval:   time.Hour,
			ActivationLeadTime: 10 * time.Minute,
			RetentionDuration:  20 * time.Minute,
			AllowedAlgorithms:  []string{keymgmt.AlgRS256},
			DefaultAlgorithm:   keymgmt.AlgRS256,
			CacheTTL:           time.Minute,
			ClockSkew:          time.Minute,
		}, keymgmt.NewMemoryRecordStore(), reversibleKeyProvider{}, keyManagerClock{}, rand.Reader, nil)
		sharedKeyMaterialSvc = services_impl.NewKeyMaterialService(nil, nil, manager, nil)
	})
	return sharedKeyMaterialSvc
}

// createDefaultTokenCreator wires the real JWT creation service over the shared
// key material. A nil options argument uses defaults. The clock is real so the
// emitted iat/nbf/exp validate against jwx's wall-clock verification.
func createDefaultTokenCreator(options *config_options.WicketOptions) services.TokenCreationService {
	if options == nil {
		options = config_options.NewWicketOptions()
	}
	return services_impl.NewTokenCreationService(sharedKeyMaterial(), test_common.NewStubClock(), options, nil)
}

// --- token model builders -------------------------------------------------

// createAccessToken builds an access token model carrying the subject, client
// id and scope claims, plus the issuer/audience/lifetime the validation side
// expects. It is used both as a reference-token payload and as the input to a
// JWT signer.
func createAccessToken(client *storage_models.Client, subjectId string, lifetime int, scopes []string) *storage_models.Token {
	tokenClaims := []*claimspkg.Claim{
		claimspkg.NewClaim(claimspkg.WithClaimType(wicket.JwtClaimTypesClientId), claimspkg.WithClaimValue(client.ClientId)),
		claimspkg.NewClaim(claimspkg.WithClaimType(wicket.JwtClaimTypesSubject), claimspkg.WithClaimValue(subjectId)),
	}
	for _, scope := range scopes {
		tokenClaims = append(tokenClaims, claimspkg.NewClaim(
			claimspkg.WithClaimType(wicket.JwtClaimTypesScope),
			claimspkg.WithClaimValue(scope),
		))
	}
	return &storage_models.Token{
		Type:         wicket.TokenTypesAccessToken,
		Issuer:       tokenTestIssuer,
		Audiences:    []string{client.ClientId},
		CreationTime: tokenTestNow,
		Lifetime:     lifetime,
		ClientId:     client.ClientId,
		Claims:       tokenClaims,
	}
}

// createAccessTokenLong appends enough padding claims to push the signed JWT
// past the configured input-length limit.
func createAccessTokenLong(client *storage_models.Client, subjectId string, lifetime int, count int, scopes []string) *storage_models.Token {
	token := createAccessToken(client, subjectId, lifetime, scopes)
	token.Claims = append(token.Claims, paddingClaims(count)...)
	return token
}

// createIdentityToken builds an identity token model whose audience is the
// requesting client, as OpenID Connect requires.
func createIdentityToken(clientId string, subjectId string) *storage_models.Token {
	return &storage_models.Token{
		Type:         wicket.TokenTypesIdentityToken,
		Issuer:       tokenTestIssuer,
		Audiences:    []string{clientId},
		CreationTime: tokenTestNow,
		Lifetime:     600,
		ClientId:     clientId,
		Claims: []*claimspkg.Claim{
			claimspkg.NewClaim(claimspkg.WithClaimType(wicket.JwtClaimTypesSubject), claimspkg.WithClaimValue(subjectId)),
		},
	}
}

// createIdentityTokenLong appends enough padding claims to push the signed JWT
// past the configured input-length limit.
func createIdentityTokenLong(clientId string, subjectId string, count int) *storage_models.Token {
	token := createIdentityToken(clientId, subjectId)
	token.Claims = append(token.Claims, paddingClaims(count)...)
	return token
}

// paddingClaims returns count distinct claims whose combined serialized size
// pushes the JWT past the input-length limit, exercising the too-long
// rejection path.
func paddingClaims(count int) []*claimspkg.Claim {
	padding := make([]*claimspkg.Claim, 0, count)
	filler := strings.Repeat("x", 64)
	for i := 0; i < count; i++ {
		padding = append(padding, claimspkg.NewClaim(
			claimspkg.WithClaimType(fmt.Sprintf("padding_%d", i)),
			claimspkg.WithClaimValue(filler),
		))
	}
	return padding
}

// --- validator wiring -----------------------------------------------------

type tokenValidatorSetup struct {
	referenceTokenStore storage.ReferenceTokenStore
	clock               services.SystemClock
}

type tokenValidatorOption func(*tokenValidatorSetup)

// withTokenValidatorStore lets a test share its reference token store with
// the validator under construction.
func withTokenValidatorStore(store storage.ReferenceTokenStore) tokenValidatorOption {
	return func(s *tokenValidatorSetup) { s.referenceTokenStore = store }
}

// withTokenValidatorClock overrides the validator's system clock, which the
// reference-token lifetime check reads.
func withTokenValidatorClock(clock services.SystemClock) tokenValidatorOption {
	return func(s *tokenValidatorSetup) { s.clock = clock }
}

// createTokenValidator wires a TokenValidator over the shared in-memory client
// fixtures with permissive defaults for every seam a caller does not override.
// The issuer and key material are wired so JWT round-trips validate; callers
// that only exercise reference tokens are unaffected by them.
func createTokenValidator(opts ...tokenValidatorOption) *TokenValidator {
	setup := &tokenValidatorSetup{}
	for _, opt := range opts {
		opt(setup)
	}
	if setup.referenceTokenStore == nil {
		setup.referenceTokenStore = createReferenceTokenStore()
	}
	var clock services.SystemClock = fixedTestClock{now: tokenTestNow}
	if setup.clock != nil {
		clock = setup.clock
	}

	clients, err := createClientStore()
	if err != nil {
		panic(err)
	}

	options := config_options.NewWicketOptions()
	options.IssuerUri = tokenTestIssuer
	return NewTokenValidator(
		test_common.NewTestLogger(),
		options,
		services_impl.NewIssuerNameService(options),
		setup.referenceTokenStore,
		NewCustomTokenValidator(),
		clients,
		validators_mock.NewTestProfileService(true),
		sharedKeyMaterial(),
		nil,
		clock,
	)
}
