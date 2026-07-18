// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package core

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket/auth"
	"github.com/gonewx/wicket/claims"
	"github.com/gonewx/wicket/hosting"
)

// SchemeProvider is registered as a singleton shared across requests, and the
// registration surface is public, so registry reads and writes synchronize on
// a lock even though assembly-time registration is single-threaded today.
type SchemeProvider struct {
	mu      sync.RWMutex
	schemes []*auth.Scheme
	options *auth.Options
}

func NewSchemeProvider(options *auth.Options) *SchemeProvider {
	if options == nil {
		options = auth.NewOptions()
	}
	return &SchemeProvider{options: options}
}

func (p *SchemeProvider) GetAllSchemes() []*auth.Scheme {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return append([]*auth.Scheme(nil), p.schemes...)
}

func (p *SchemeProvider) GetScheme(name string) *auth.Scheme {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.findScheme(name)
}

// findScheme scans the registry without locking; callers hold p.mu.
func (p *SchemeProvider) findScheme(name string) *auth.Scheme {
	for _, scheme := range p.schemes {
		if scheme.Name == name {
			return scheme
		}
	}
	return nil
}

// Default-scheme resolution comes strictly from configuration, never from an
// implicitly-chosen registered scheme. Each category consults its own configured
// default and falls back through a chain that ends at the overall DefaultScheme.
// Sign-out falls back to the sign-in default; forbid falls back to the challenge
// default. Fallback does not check whether the resolved scheme declares the
// matching handler capability.

func (p *SchemeProvider) GetDefaultAuthenticateScheme() *auth.Scheme {
	return p.schemeByName(p.defaultAuthenticateName())
}

func (p *SchemeProvider) GetDefaultChallengeScheme() *auth.Scheme {
	return p.schemeByName(p.defaultChallengeName())
}

func (p *SchemeProvider) GetDefaultForbidScheme() *auth.Scheme {
	return p.schemeByName(firstNonEmpty(p.options.DefaultForbidScheme, p.defaultChallengeName()))
}

func (p *SchemeProvider) GetDefaultSignInScheme() *auth.Scheme {
	return p.schemeByName(p.defaultSignInName())
}

func (p *SchemeProvider) GetDefaultSignOutScheme() *auth.Scheme {
	return p.schemeByName(firstNonEmpty(p.options.DefaultSignOutScheme, p.defaultSignInName()))
}

func (p *SchemeProvider) defaultAuthenticateName() string {
	return firstNonEmpty(p.options.DefaultAuthenticateScheme, p.options.DefaultScheme)
}

func (p *SchemeProvider) defaultChallengeName() string {
	return firstNonEmpty(p.options.DefaultChallengeScheme, p.options.DefaultScheme)
}

func (p *SchemeProvider) defaultSignInName() string {
	return firstNonEmpty(p.options.DefaultSignInScheme, p.options.DefaultScheme)
}

// schemeByName resolves a configured default name to a registered scheme; an
// empty name (no default configured) yields no scheme.
func (p *SchemeProvider) schemeByName(name string) *auth.Scheme {
	if name == "" {
		return nil
	}
	return p.GetScheme(name)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func (p *SchemeProvider) AddScheme(scheme *auth.Scheme) error {
	if scheme == nil {
		return fmt.Errorf("auth scheme is nil")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.findScheme(scheme.Name) != nil {
		return fmt.Errorf("auth scheme %q already exists", scheme.Name)
	}
	p.schemes = append(p.schemes, scheme)
	return nil
}

func (p *SchemeProvider) TryAddScheme(scheme *auth.Scheme) bool {
	if scheme == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.findScheme(scheme.Name) != nil {
		return false
	}
	p.schemes = append(p.schemes, scheme)
	return true
}

// RemoveScheme drops the named scheme and reports whether it was present. A
// removed name is released for re-registration.
func (p *SchemeProvider) RemoveScheme(name string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, scheme := range p.schemes {
		if scheme.Name == name {
			p.schemes = append(p.schemes[:i], p.schemes[i+1:]...)
			return true
		}
	}
	return false
}

// GetRequestHandlerSchemes lists the registered schemes marked as request
// handlers. The capability travels on the scheme record because handlers are
// resolved per request and the registry is the only static knowledge source.
func (p *SchemeProvider) GetRequestHandlerSchemes() ([]*auth.Scheme, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	var schemes []*auth.Scheme
	for _, scheme := range p.schemes {
		if scheme.HandlesRequests {
			schemes = append(schemes, scheme)
		}
	}
	return schemes, nil
}

type HandlerProvider struct {
	schemes  auth.SchemeProvider
	provider godi.Provider
	handlers map[string]auth.Handler
}

func NewHandlerProvider(schemes auth.SchemeProvider, provider godi.Provider) *HandlerProvider {
	return &HandlerProvider{schemes: schemes, provider: provider, handlers: map[string]auth.Handler{}}
}

// GetHandler resolves the handler for a scheme name through the request scope,
// keyed by the scheme name, initializes it, and reuses it for the remainder of
// the request. An unregistered scheme yields no handler and no error; a
// registered scheme with no resolvable handler yields an error naming it.
func (p *HandlerProvider) GetHandler(request *http.Request, response http.ResponseWriter, schemeName string) (auth.Handler, error) {
	if cached, ok := p.handlers[schemeName]; ok {
		return cached, nil
	}
	scheme := p.schemes.GetScheme(schemeName)
	if scheme == nil {
		return nil, nil
	}
	handler, ok := godi.GetKeyed[auth.Handler](p.provider, schemeName)
	if !ok || handler == nil {
		return nil, fmt.Errorf("no authentication handler registered for scheme %q", schemeName)
	}
	if err := handler.Initialize(request, response, scheme); err != nil {
		return nil, err
	}
	p.handlers[schemeName] = handler
	return handler, nil
}

type NoopClaimsTransformation struct{}

func NewNoopClaimsTransformation() *NoopClaimsTransformation {
	return &NoopClaimsTransformation{}
}

func (NoopClaimsTransformation) Transform(principal *claims.ClaimsPrincipal) (*claims.ClaimsPrincipal, error) {
	return principal, nil
}

type Service struct {
	schemes  auth.SchemeProvider
	handlers auth.HandlerProvider
}

func NewService(schemes auth.SchemeProvider, handlers auth.HandlerProvider) *Service {
	return &Service{schemes: schemes, handlers: handlers}
}

func (s *Service) Authenticate(r *http.Request, w http.ResponseWriter, scheme string) (*auth.Result, error) {
	handler, err := s.handlers.GetHandler(r, w, scheme)
	if err != nil || handler == nil {
		return auth.NoResult(), err
	}
	return handler.Authenticate()
}

func (s *Service) Challenge(r *http.Request, w http.ResponseWriter, scheme string, properties *auth.Properties) error {
	handler, err := s.handlers.GetHandler(r, w, scheme)
	if err != nil || handler == nil {
		return err
	}
	return handler.Challenge(properties)
}

func (s *Service) Forbid(r *http.Request, w http.ResponseWriter, scheme string, properties *auth.Properties) error {
	handler, err := s.handlers.GetHandler(r, w, scheme)
	if err != nil || handler == nil {
		return err
	}
	return handler.Forbid(properties)
}

func (s *Service) SignIn(r *http.Request, w http.ResponseWriter, scheme string, principal *claims.ClaimsPrincipal, properties *auth.Properties) error {
	if scheme == "" {
		if def := s.schemes.GetDefaultSignInScheme(); def != nil {
			scheme = def.Name
		}
	}
	handler, err := s.handlers.GetHandler(r, w, scheme)
	if err != nil || handler == nil {
		return err
	}
	if signIn, ok := handler.(auth.SignInHandler); ok {
		return signIn.SignIn(principal, properties)
	}
	return fmt.Errorf("sign-in is unsupported")
}

func (s *Service) SignOut(r *http.Request, w http.ResponseWriter, scheme string, properties *auth.Properties) error {
	if scheme == "" {
		if def := s.schemes.GetDefaultSignOutScheme(); def != nil {
			scheme = def.Name
		}
	}
	handler, err := s.handlers.GetHandler(r, w, scheme)
	if err != nil || handler == nil {
		return err
	}
	if signOut, ok := handler.(auth.SignOutHandler); ok {
		return signOut.SignOut(properties)
	}
	return fmt.Errorf("sign-out is unsupported")
}

type resultContextKey struct{}

// ContextWithResult returns a context carrying the authentication result for
// downstream consumers.
func ContextWithResult(ctx context.Context, result *auth.Result) context.Context {
	return context.WithValue(ctx, resultContextKey{}, result)
}

// ResultFromContext returns the authentication result placed on the context by
// the middleware, or nil when the request is anonymous.
func ResultFromContext(ctx context.Context) *auth.Result {
	if result, ok := ctx.Value(resultContextKey{}).(*auth.Result); ok {
		return result
	}
	return nil
}

func Middleware(provider auth.SchemeProvider, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if scheme := provider.GetDefaultAuthenticateScheme(); scheme != nil {
				if scope := hosting.ScopeFrom(r.Context()); scope != nil {
					if handlers, ok := godi.Get[auth.HandlerProvider](scope); ok && handlers != nil {
						handler, err := handlers.GetHandler(r, w, scheme.Name)
						switch {
						case err != nil:
							logWarn(logger, "authentication handler resolution failed", scheme.Name, err)
						case handler != nil:
							result, err := handler.Authenticate()
							switch {
							case err != nil:
								logWarn(logger, "authentication failed for the default scheme", scheme.Name, err)
							case result != nil && !result.None:
								r = r.WithContext(ContextWithResult(r.Context(), result))
							}
						}
					}
				}
			}
			// Request-handler schemes claim their own callback paths — an
			// external identity provider return leg, for instance. After the
			// default authenticate pass above, they are enumerated and driven
			// when one owns the current request; a handled request has already
			// written its own response, so the pipeline short-circuits here
			// and never descends. A resolution, contract, or processing
			// failure only warns: the request falls through to the downstream
			// pipeline rather than failing outright.
			if schemes, err := provider.GetRequestHandlerSchemes(); err != nil {
				logWarn(logger, "request-handler scheme enumeration failed", "", err)
			} else if len(schemes) > 0 {
				if scope := hosting.ScopeFrom(r.Context()); scope != nil {
					if handlers, ok := godi.Get[auth.HandlerProvider](scope); ok && handlers != nil {
						for _, scheme := range schemes {
							handler, err := handlers.GetHandler(r, w, scheme.Name)
							if err != nil {
								logWarn(logger, "request-handler resolution failed", scheme.Name, err)
								continue
							}
							if handler == nil {
								continue
							}
							requestHandler, ok := handler.(auth.RequestHandler)
							if !ok {
								logWarn(logger, "request-handler contract not implemented", scheme.Name,
									fmt.Errorf("handler type %T does not implement auth.RequestHandler", handler))
								continue
							}
							if !requestHandler.ShouldHandleRequest() {
								continue
							}
							handled, err := requestHandler.HandleRequest()
							if err != nil {
								logWarn(logger, "request-handler processing failed", scheme.Name, err)
							}
							if handled {
								return
							}
						}
					}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// logWarn records a middleware failure. The middleware never fails the
// request on an error — the request proceeds anonymously — so the log entry
// is the only diagnostic signal.
func logWarn(logger *slog.Logger, message, scheme string, err error) {
	if logger != nil {
		logger.Warn(message, slog.String("scheme", scheme), slog.Any("error", err))
	}
}

// NewUnsupportedHandler builds a handler for a scheme whose concrete handler is
// not yet available. It authenticates to no result and rejects challenge and
// forbid, serving as the keyed registration for such schemes.
func NewUnsupportedHandler() auth.Handler {
	return &unsupportedHandler{}
}

type unsupportedHandler struct {
	scheme *auth.Scheme
}

func (h *unsupportedHandler) Initialize(request *http.Request, response http.ResponseWriter, scheme *auth.Scheme) error {
	h.scheme = scheme
	return nil
}

func (h *unsupportedHandler) Authenticate() (*auth.Result, error) { return auth.NoResult(), nil }
func (h *unsupportedHandler) Challenge(*auth.Properties) error {
	return fmt.Errorf("challenge is unsupported")
}
func (h *unsupportedHandler) Forbid(*auth.Properties) error {
	return fmt.Errorf("forbid is unsupported")
}
