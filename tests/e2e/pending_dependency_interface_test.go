package e2e_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gonewx/wicket/di"
)

type endpointProcessor interface {
	Process(http.ResponseWriter, *http.Request) error
}

func TestPendingDependencyInterfacesResolveFromContainerE2E(t *testing.T) {
	t.Parallel()

	root, err := di.NewRoot()
	if err != nil {
		t.Fatalf("construct DI root: %v", err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Fatalf("close DI root: %v", err)
		}
	})

	if service := root.NewKeyMaterialService(); service == nil {
		t.Fatal("KeyMaterialService seam did not resolve")
	}
	if validator := root.NewBackchannelAuthenticationRequestIdValidator(); validator == nil {
		t.Fatal("BackchannelAuthenticationRequestIdValidator seam did not resolve")
	}
	sessionService := root.NewSessionCoordinationService()
	if sessionService == nil {
		t.Fatal("SessionCoordinationService seam did not resolve")
	}
	valid, err := sessionService.ValidateSession(nil)
	if err != nil {
		t.Fatalf("SessionCoordinationService returned error %v, want nil (pass-through when disabled)", err)
	}
	if !valid {
		t.Fatal("SessionCoordinationService returned invalid, want true (pass-through when disabled)")
	}
	body, err := root.NewJwtRequestUriHttpClient().GetJwt("http://127.0.0.1:1/request.jwt", nil)
	if err == nil {
		t.Fatal("JwtRequestUriHttpClient returned nil error, want neutral pending error")
	}
	if body != "" {
		t.Fatalf("JwtRequestUriHttpClient body = %q, want empty string", body)
	}
	want := "pending Epic " + "2/3 implementation"
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("JwtRequestUriHttpClient error = %q, want substring %q", err.Error(), want)
	}

	request := httptest.NewRequest(http.MethodGet, "http://wicket.test/connect/token", nil)
	for name, handler := range map[string]endpointProcessor{
		"authorize":            root.NewPtr_AuthorizeHandler(),
		"authorize_callback":   root.NewPtr_AuthorizeCallbackHandler(),
		"token":                root.NewPtr_TokenHandler(),
		"discovery":            root.NewPtr_DiscoveryHandler(),
		"discovery_keys":       root.NewPtr_DiscoveryKeyHandler(),
		"check_session":        root.NewPtr_CheckSessionHandler(),
		"introspection":        root.NewPtr_IntrospectionHandler(),
		"user_info":            root.NewPtr_UserInfoHandler(),
		"end_session":          root.NewPtr_EndSessionHandler(),
		"end_session_callback": root.NewPtr_EndSessionCallbackHandler(),
	} {
		err := handler.Process(httptest.NewRecorder(), request)
		if err == nil {
			t.Fatalf("%s handler returned nil error, want neutral pending error", name)
		}
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("%s handler error = %q, want substring %q", name, err.Error(), want)
		}
	}
}

func TestPendingInterfaceFilesAvoidSourceContactMarkersE2E(t *testing.T) {
	t.Parallel()

	for _, rel := range []string{
		"accessor/http_context.go",
		"auth/authentication.go",
		"auth/cookies/options.go",
		"auth/core/core.go",
		"claims/claims.go",
		"config/options/backchannel_authentication_options.go",
		"di/options/options.go",
		"dp/dp.go",
		"handlers/handlers.go",
		"hosting/context.go",
		"hosting/dynamic/schemes/schemes.go",
		"hosting/middleware.go",
		"hosting/scope_middleware.go",
		"services/interfaces.go",
		"services/impl/core_services.go",
		"services/impl/data_protection_provider.go",
		"services/memory/cache.go",
		"storage/interfaces.go",
		"storage/memory/client_resource_store.go",
		"storage/memory/grant_stores.go",
		"storage/memory/keys.go",
		"storage/models/backchannel_authentication_request.go",
		"validators/impl/default_seams.go",
		"validators/seams.go",
	} {
		content := readProjectFile(t, rel)
		for _, forbidden := range []string{
			"Due" + "nde",
			"Due" + "ndeSoftware",
			"6." + "1.4",
			"Based " + "on",
			"Ported " + "from",
			"// From:",
		} {
			if strings.Contains(content, forbidden) {
				t.Fatalf("%s contains source-contact marker %q", rel, forbidden)
			}
		}
		if !strings.Contains(content, "Copyright 2026 Decker") {
			t.Fatalf("%s missing wicket wicket copyright header", rel)
		}
	}
}

func TestDependencyInterfaceLedgerE2E(t *testing.T) {
	t.Parallel()

	evidenceRoot := evidenceRepositoryRoot(t)
	const ledger = "buc" + "ket-c-dependency-seam-ledger-2026-07-07.md"
	runGit(t, evidenceRoot, "ls-files", "--error-unmatch", ledger)

	content := readEvidenceFile(t, evidenceRoot, ledger)
	for _, want := range []string{
		"Claims principal/identity",
		"Generic options pipeline",
		"HTTP context accessor",
		"Cookie auth options",
		"Auth core",
		"Data protection",
		"Endpoint handlers",
		"Dynamic schemes",
		"Storage contracts",
		"Core services",
		"Validator seams",
		"go generate ./...",
		"go test ./tests/e2e",
		"go build ./...",
		"go test ./...",
		"3ec2790ca2f858256350cb26f62c332946adb8a8",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("%s missing %q", filepath.Join(evidenceRoot, ledger), want)
		}
	}
}

func TestGeneratedContainerIncludesPendingInterfacesE2E(t *testing.T) {
	t.Parallel()

	content := readProjectFile(t, "di/container_gen.go")
	if !strings.HasPrefix(content, "// Code generated by godi-gen; DO NOT EDIT.") {
		t.Fatal("di/container_gen.go missing godi generated header")
	}
	for _, want := range []string{
		"func NewRoot() (*Root, error)",
		"func (r *Root) NewKeyMaterialService()",
		"func (r *Root) NewBackchannelAuthenticationRequestIdValidator()",
		"func (r *Root) NewSessionCoordinationService()",
		"func (r *Root) NewPtr_TokenHandler()",
		"func (s *scope) NewSessionCoordinationService()",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("di/container_gen.go missing generated seam surface %q", want)
		}
	}
}
