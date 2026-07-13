// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package common

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/auth"
	authcore "github.com/gonewx/wicket/auth/core"
	claimspkg "github.com/gonewx/wicket/claims"
	client_messages "github.com/gonewx/wicket/client/messages"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/di"
	"github.com/gonewx/wicket/extensions"
	"github.com/gonewx/wicket/hosting"
	"github.com/gonewx/wicket/models"
	"github.com/gonewx/wicket/models/messages"
	"github.com/gonewx/wicket/server"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/storage"
	storage_memory "github.com/gonewx/wicket/storage/memory"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/test"
	"github.com/gonewx/wicket/tokens"
	"github.com/gonewx/wicket/utils"
	"github.com/gonewx/wicket/validators"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

var (
	// gois: golang test server base url dynamically generated
	// BaseUrl     = "https://server"
	LoginPage   = "/account/login"
	LogoutPage  = "/account/logout"
	ConsentPage = "/account/consent"
	ErrorPage   = "/home/error"

	DeviceAuthorization               = "/connect/deviceauthorization"
	DiscoveryEndpoint                 = "/.well-known/openid-configuration"
	DiscoveryKeysEndpoint             = "/.well-known/openid-configuration/jwks"
	AuthorizeEndpoint                 = "/connect/authorize"
	BackchannelAuthenticationEndpoint = "/connect/ciba"
	TokenEndpoint                     = "/connect/token"
	RevocationEndpoint                = "/connect/revocation"
	UserInfoEndpoint                  = "/connect/userinfo"
	IntrospectionEndpoint             = "/connect/introspect"
	IdentityTokenValidationEndpoint   = "/connect/identityTokenValidation"
	EndSessionEndpoint                = "/connect/endsession"
	EndSessionCallbackEndpoint        = "/connect/endsession/callback"
	CheckSessionEndpoint              = "/connect/checksession"

	FederatedSignOutPath = "/signout-oidc"
	FederatedSignOutUrl  = FederatedSignOutPath
)

type WicketPipeline struct {
	Options           *config_options.WicketOptions
	TestServer        *httptest.Server
	BrowserClient     *BrowserClient
	BackChannelClient *http.Client

	BackChannelMessageHandler *mockMessageHandler
	JwtRequestMessageHandler  *mockMessageHandler

	Server *server.Server
	Root   *di.Root

	Clients                                []*storage_models.Client
	IdentityScopes                         []*storage_models.IdentityResource
	ApiResources                           []*storage_models.ApiResource
	ApiScopes                              []*storage_models.ApiScope
	SigningCredentialStores                []storage.SigningCredentialStore
	ValidationKeysStores                   []storage.ValidationKeysStore
	Users                                  []*test.TestUser
	UserStore                              *test.TestUserStore
	Profile                                services.ProfileService
	ResourceOwnerValidator                 validators.ResourceOwnerPasswordValidator
	BackchannelAuthenticationUserValidator validators.BackchannelAuthenticationUserValidator

	LoginWasCalled bool
	LoginReturnUrl string
	LoginRequest   *messages.AuthorizationRequest
	Subject        *claimspkg.ClaimsPrincipal

	LogoutWasCalled bool
	LogoutRequest   *messages.LogoutRequest

	ErrorWasCalled bool
	ErrorMessage   *messages.ErrorMessage

	ConsentWasCalled bool
	ConsentRequest   *messages.AuthorizationRequest
	ConsentResponse  *messages.ConsentResponse

	CustomWasCalled bool
	CustomRequest   *messages.AuthorizationRequest

	AuthorizationParametersMessageStore storage.AuthorizationParametersMessageStore
}

func NewWicketPipeline() *WicketPipeline {
	p := &WicketPipeline{
		BackChannelMessageHandler: newMockMessageHandler(),
		JwtRequestMessageHandler:  newMockMessageHandler(),
		IdentityScopes:            make([]*storage_models.IdentityResource, 0),
		ApiResources:              make([]*storage_models.ApiResource, 0),
		ApiScopes:                 make([]*storage_models.ApiScope, 0),
		Users:                     make([]*test.TestUser, 0),
	}

	var err error
	p.Root, err = di.NewRoot()
	if err != nil {
		panic(err)
	}
	p.Server, err = server.DefaultServer(
		p.Root,
		server.WithLogger(p.Root.Ptr_Logger()),
	)
	if err != nil {
		panic(err)
	}

	return p
}

func (p *WicketPipeline) createInteractionService(r *http.Request) services.InteractionService {
	// AD-10: integration host resolves interaction service from the request scope.
	return godi.GetRequired[services.InteractionService](hosting.ScopeFrom(r.Context()))
}

func (p *WicketPipeline) onLogin() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p.LoginWasCalled = true

		p.readLoginRequest(r, w)
		p.issueLoginCookie(r, w)
	}
}

func (p *WicketPipeline) readLoginRequest(r *http.Request, w http.ResponseWriter) {
	var err error

	interaction := p.createInteractionService(r)
	// p.LoginReturnUrl = r.Header.Get(p.Options.UserInteraction.LoginReturnUrlParameter)
	p.LoginReturnUrl = r.URL.Query().Get(p.Options.UserInteraction.LoginReturnUrlParameter)
	p.LoginRequest, err = interaction.GetAuthorizationContext(p.LoginReturnUrl)
	if err != nil {
		panic(err)
	}
}

func service(ctx context.Context) (auth.Service, error) {
	if ctx == nil {
		return nil, gois.InvalidOperationException
	}

	return godi.GetRequired[auth.Service](hosting.ScopeFrom(ctx)), nil
}

func (p *WicketPipeline) issueLoginCookie(r *http.Request, w http.ResponseWriter) {
	if p.Subject == nil {
		return
	}

	props := auth.NewProperties()

	ctx := r.Context()
	svc, err := service(ctx)
	if err != nil {
		panic(err)
	}

	err = svc.SignIn(r, w, gois.DefaultCookieAuthenticationScheme, p.Subject, props)
	if err != nil {
		panic(err)
	}

	p.Subject = nil

	u := r.URL.Query().Get(p.Options.UserInteraction.LoginReturnUrlParameter)
	if u != "" {
		http.Redirect(w, r, u, http.StatusFound)
		return
	}
	w.WriteHeader(http.StatusOK)

}

func (p *WicketPipeline) onLogout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p.LogoutWasCalled = true

		p.readLogoutRequest(r, w)

		ctx := r.Context()
		svc, err := service(ctx)
		if err != nil {
			panic(err)
		}
		err = svc.SignOut(r, w, "", nil)
		if err != nil {
			panic(err)
		}

		w.WriteHeader(http.StatusOK)
	}
}

func (p *WicketPipeline) readLogoutRequest(r *http.Request, w http.ResponseWriter) {
	var err error

	interaction := p.createInteractionService(r)
	p.LogoutRequest, err = interaction.GetLogoutContext(r.URL.Query().Get("logoutId"))
	if err != nil {
		panic(err)
	}
}

func (p *WicketPipeline) onConsent() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p.ConsentWasCalled = true

		p.readConsentRequest(r, w)
		p.createConsentResponse(r, w)
	}
}

func (p *WicketPipeline) readConsentRequest(r *http.Request, w http.ResponseWriter) {
	var err error

	interaction := p.createInteractionService(r)
	p.ConsentRequest, err = interaction.GetAuthorizationContext(r.URL.Query().Get("returnUrl"))
	if err != nil {
		panic(err)
	}
}

func (p *WicketPipeline) createConsentResponse(r *http.Request, w http.ResponseWriter) {
	if p.ConsentRequest == nil || p.ConsentResponse == nil {
		return
	}

	interaction := p.createInteractionService(r)
	err := interaction.GrantConsent(p.ConsentRequest, p.ConsentResponse, "")
	if err != nil {
		panic(err)
	}

	p.ConsentResponse = nil

	url := r.URL.Query().Get(p.Options.UserInteraction.ConsentReturnUrlParameter)
	if url != "" {
		http.Redirect(w, r, url, http.StatusFound)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (p *WicketPipeline) onCustom() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p.CustomWasCalled = true

		var err error
		interaction := p.createInteractionService(r)
		p.CustomRequest, err = interaction.GetAuthorizationContext(r.URL.Query().Get(p.Options.UserInteraction.ConsentReturnUrlParameter))
		if err != nil {
			panic(err)
		}
	}
}

func (p *WicketPipeline) onError() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p.ErrorWasCalled = true

		p.readErrorMessage(r, w)
		w.WriteHeader(http.StatusOK)

	}
}

func (p *WicketPipeline) readErrorMessage(r *http.Request, w http.ResponseWriter) {
	var err error
	interaction := p.createInteractionService(r)

	p.ErrorMessage, err = interaction.GetErrorContext(r.URL.Query().Get("errorId"))
	if err != nil {
		panic(err)
	}
}

func (p *WicketPipeline) LoginWithPrincipal(subject *claimspkg.ClaimsPrincipal) error {
	old := p.BrowserClient.AllowAutoRedirect
	p.BrowserClient.AllowAutoRedirect = false

	p.Subject = subject

	u, err := url.JoinPath(p.TestServer.URL, LoginPage)
	if err != nil {
		return err
	}
	_, err = p.BrowserClient.Get(u)
	if err != nil {
		return err
	}

	p.BrowserClient.AllowAutoRedirect = old
	return nil
}

func (p *WicketPipeline) Login(subject string) error {
	user, err := models.NewLocalUser(models.WithLocalUserSubjectId(subject)).CreatePrincipal()
	if err != nil {
		return err
	}
	return p.LoginWithPrincipal(user)
}

func (p *WicketPipeline) RemoveLoginCookie() {
	p.BrowserClient.RemoveCookie(p.TestServer.URL, gois.DefaultCookieAuthenticationScheme)
}

func (p *WicketPipeline) RemoveSessionCookie() {
	p.BrowserClient.RemoveCookie(p.TestServer.URL, gois.DefaultCheckSessionCookieName)
}

func (p *WicketPipeline) GetSessionCookie() *http.Cookie {
	return p.BrowserClient.GetCookie(p.TestServer.URL, gois.DefaultCheckSessionCookieName)
}

func (p *WicketPipeline) Initialize() {

	p.Options = godi.GetRequired[*config_options.WicketOptions](p.Root)
	p.Options.KeyManagement.Enabled = false

	// Host wiring the cookie-options post-configuration would normally apply:
	// interaction pages default to the host account routes.
	if p.Options.UserInteraction.LoginUrl == "" {
		p.Options.UserInteraction.LoginUrl = gois.UIConstantsDefaultRoutePathsLogin
	}
	if p.Options.UserInteraction.LoginReturnUrlParameter == "" {
		p.Options.UserInteraction.LoginReturnUrlParameter = gois.UIConstantsDefaultRoutePathParamsLogin
	}
	if p.Options.UserInteraction.LogoutUrl == "" {
		p.Options.UserInteraction.LogoutUrl = gois.UIConstantsDefaultRoutePathsLogout
	}

	p.UserStore = test.NewTestUserStore(p.Users)

	p.Profile = test.NewTestUserProfileService(p.UserStore, p.Server.Logger)

	p.configureServices()

	wicketMiddleware := p.Server.UseWicket()

	mux := http.NewServeMux()
	mux.HandleFunc(utils.EnsureLeadingSlash(gois.UIConstantsDefaultRoutePathsLogin), p.onLogin())
	mux.HandleFunc(utils.EnsureLeadingSlash(gois.UIConstantsDefaultRoutePathsLogout), p.onLogout())
	mux.HandleFunc(utils.EnsureLeadingSlash(gois.UIConstantsDefaultRoutePathsConsent), p.onConsent())
	mux.HandleFunc("/custom", p.onCustom())
	mux.HandleFunc(utils.EnsureLeadingSlash(gois.UIConstantsDefaultRoutePathsError), p.onError())

	p.TestServer = httptest.NewServer(hosting.ScopeMiddleware(p.Root)(wicketMiddleware(mux)))
	p.TestServer.Config.RegisterOnShutdown(func() {
		_ = p.Root.Close()
	})
	client := p.TestServer.Client()

	p.BrowserClient = NewBrowserClient(client)
	p.BackChannelClient = &http.Client{}

}

func (p *WicketPipeline) configureServices() {
	p.ResourceOwnerValidator = test.NewTestUserResourceOwnerPasswordValidator(p.UserStore, godi.GetRequired[services.SystemClock](p.Root))
	p.BackChannelClient = &http.Client{Transport: p.BackChannelMessageHandler}
	p.AddDeveloperSigningCredential(jwa.RS256)

	cfg := p.Root.ServerConfig()
	cfg.SetSigningCredentialStoresProvider(func() []storage.SigningCredentialStore {
		return p.SigningCredentialStores
	})
	cfg.SetValidationKeysStoresProvider(func() []storage.ValidationKeysStore {
		return p.ValidationKeysStores
	})
	cfg.SetClientsProvider(func() []*storage_models.Client {
		return p.Clients
	})
	cfg.SetIdentityScopesProvider(func() []*storage_models.IdentityResource {
		return p.IdentityScopes
	})
	cfg.SetApiResourcesProvider(func() []*storage_models.ApiResource {
		return p.ApiResources
	})
	cfg.SetApiScopesProvider(func() []*storage_models.ApiScope {
		return p.ApiScopes
	})
	cfg.SetAuthorizationParametersMessageStoreProvider(func() storage.AuthorizationParametersMessageStore {
		return p.AuthorizationParametersMessageStore
	})
	cfg.SetBackchannelAuthenticationUserValidator(p.BackchannelAuthenticationUserValidator)
	cfg.SetResourceOwnerValidator(p.ResourceOwnerValidator)
	cfg.SetProfileProvider(func() services.ProfileService { return p.Profile })
	cfg.SetBackChannelLogoutHttpClient(p.BackChannelClient)
	cfg.SetAuthenticationHandlerProvider(gois.DefaultCookieAuthenticationScheme, func(prov godi.Provider) auth.Handler {
		return newTestCookieAuthenticationHandler(godi.GetRequired[services.UserSession](prov))
	})
	// Host startup registers the default cookie scheme so the scheme registry
	// can resolve it; the handler itself comes from the seam above.
	if err := godi.GetRequired[*authcore.SchemeProvider](p.Root).AddScheme(
		auth.NewScheme(gois.DefaultCookieAuthenticationScheme, "testCookieAuthenticationHandler"),
	); err != nil {
		panic(err)
	}
	cfg.Freeze()

}

func (p *WicketPipeline) AddDeveloperSigningCredential(signingAlgorithm jwa.SignatureAlgorithm) {
	raw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	kidKey, err := jwk.FromRaw(raw)
	if err != nil {
		panic(err)
	}
	if err := jwk.AssignKeyID(kidKey); err != nil {
		panic(err)
	}
	credential, err := tokens.NewSigningCredentials(raw, tokens.WithAlgorithm(string(signingAlgorithm)), tokens.WithKid(kidKey.KeyID()))
	if err != nil {
		panic(err)
	}
	p.AddSigningCredential(credential)
}

func (p *WicketPipeline) AddSigningCredential(credential *tokens.SigningCredentials) {
	if !utils.Contains(gois.SupportedSigningAlgorithms, credential.Algorithm) {
		panic(fmt.Sprintf("credential.Algorithm is not supported %s", credential.Algorithm))
	}
	p.SigningCredentialStores = append(p.SigningCredentialStores, storage_memory.NewMemorySigningCredentialStore(credential))
	p.AddValidationKey([]*models.SecurityKeyInfo{
		{
			Key:              publicKeyOf(credential.Key),
			SigningAlgorithm: credential.Algorithm,
		},
	})
}

func (p *WicketPipeline) AddValidationKey(keys []*models.SecurityKeyInfo) {
	p.ValidationKeysStores = append(p.ValidationKeysStores, storage_memory.NewMemoryValidationKeysStore(keys))
}

type AuthorizeUrl struct {
	ClientId            string
	ResponseType        string
	Scope               string
	RedirectUri         string
	State               string
	Nonce               string
	LoginHint           string
	AcrValues           string
	ResponseMode        string
	CodeChallenge       string
	CodeChallengeMethod string
	Extra               url.Values
}

func (p *WicketPipeline) CreateAuthorizeUrl(au *AuthorizeUrl) (*url.URL, error) {

	rawURL, err := url.JoinPath(p.TestServer.URL, gois.ProtocolRoutePathsAuthorize)
	if err != nil {
		return nil, err
	}

	baseUrl, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}

	return extensions.CreateAuthorizeUrl(
		baseUrl,
		au.ClientId,
		au.ResponseType,
		au.Scope,
		au.RedirectUri,
		au.State,
		au.Nonce,
		au.LoginHint,
		au.AcrValues,
		"",
		au.ResponseMode,
		au.CodeChallenge,
		au.CodeChallengeMethod,
		"",
		0,
		"",
		"",
		au.Extra,
	), nil
}

func (p *WicketPipeline) ParseAuthorizationResponseUrl(u string) *client_messages.AuthorizeResponse {
	return client_messages.NewAuthorizeResponse(u)
}

func (p *WicketPipeline) RequestAuthorizationEndpoint(
	authorizeUrl *AuthorizeUrl,
) *client_messages.AuthorizeResponse {
	old := p.BrowserClient.AllowAutoRedirect
	p.BrowserClient.AllowAutoRedirect = false

	u, err := p.CreateAuthorizeUrl(authorizeUrl)
	if err != nil {
		panic(err)
	}

	resp, err := p.BrowserClient.Get(u.String())
	if err != nil {
		panic(err)
	}
	if resp.StatusCode != http.StatusFound {
		panic(fmt.Errorf("unexpected status code: %d", resp.StatusCode))
	}

	p.BrowserClient.AllowAutoRedirect = old

	location := resp.Header.Get("Location")
	redirect, err := url.Parse(location)
	if err != nil {
		panic(err)
	}

	if strings.HasPrefix(redirect.Path, ErrorPage) {
		// request error page in pipeline so we can get error info
		_, _ = p.BrowserClient.Get(location)

		// no redirect to client
		return nil
	}

	return client_messages.NewAuthorizeResponse(location)
}

type mockMessageHandler struct {
	core http.RoundTripper

	InvokeWasCalled bool
	OnInvoke        func(r *http.Request) error
	Response        *http.Response
}

func newMockMessageHandler() *mockMessageHandler {
	return &mockMessageHandler{
		core: http.DefaultTransport,
		Response: &http.Response{
			StatusCode: http.StatusOK,
		},
	}
}

func (h *mockMessageHandler) RoundTrip(r *http.Request) (*http.Response, error) {
	defer func() {
		_ = r.Body.Close()
	}()

	h.InvokeWasCalled = true

	if h.OnInvoke != nil {
		err := h.OnInvoke(r)
		if err != nil {
			return nil, err
		}
	}

	// send the request using the DefaultTransport
	// return h.core.RoundTrip(r)
	return h.Response, nil
}

var _ auth.Handler = (*mockExternalAuthenticationHandler)(nil)
var _ auth.SignInHandler = (*mockExternalAuthenticationHandler)(nil)
var _ auth.RequestHandler = (*mockExternalAuthenticationHandler)(nil)

type mockExternalAuthenticationHandler struct {
	// httpContextAccessor accessor.HttpContextAccessor
	request *http.Request

	OnFederatedSignout func() (bool, error)
}

func newMockExternalAuthenticationHandler(request *http.Request) *mockExternalAuthenticationHandler {
	return &mockExternalAuthenticationHandler{
		request: request,
	}
}

func (h *mockExternalAuthenticationHandler) ShouldHandleRequest() bool {
	return h.request.URL.Path == FederatedSignOutPath
}

func (h *mockExternalAuthenticationHandler) HandleRequest() (bool, error) {
	if h.request.URL.Path == FederatedSignOutPath {
		return h.OnFederatedSignout()
	}
	return false, nil
}

func (h *mockExternalAuthenticationHandler) Authenticate() (*auth.Result, error) {
	return auth.NoResult(), nil
}

func (h *mockExternalAuthenticationHandler) Challenge(properties *auth.Properties) error {
	return nil
}

func (h *mockExternalAuthenticationHandler) Forbid(properties *auth.Properties) error {
	return nil
}

func (h *mockExternalAuthenticationHandler) Initialize(request *http.Request, response http.ResponseWriter, scheme *auth.Scheme) error {
	return nil
}

func (h *mockExternalAuthenticationHandler) SignIn(user *claimspkg.ClaimsPrincipal, properties *auth.Properties) error {
	return nil
}

func (h *mockExternalAuthenticationHandler) SignOut(properties *auth.Properties) error {
	return nil
}

func (h *mockExternalAuthenticationHandler) FinishResponse() error {
	return nil
}

// publicKeyOf projects a signing key to its public form. Validation keys feed
// the published JWKS, so a private key must never be handed to that store.
func publicKeyOf(key any) any {
	if signer, ok := key.(interface{ Public() crypto.PublicKey }); ok {
		return signer.Public()
	}
	return key
}
