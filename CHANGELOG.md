# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Token revocation endpoint (RFC 7009) at `POST /connect/revocation`, handled by `handlers.TokenRevocationHandler` and registered through the composition root. With `EnableTokenRevocationEndpoint` off it answers 404 and is not advertised. Clients authenticate as at the token endpoint. A failed client authentication answers `invalid_client`: 401 with a `WWW-Authenticate` challenge (`Basic realm="wicket"` for Basic) when the request carries an `Authorization` header, 400 otherwise. A missing token answers 400 `invalid_request`, as does an empty body when the credentials are in the `Authorization` header (with no such header an empty body carries no credentials and answers 400 `invalid_client`); a `token_type_hint` other than `access_token` / `refresh_token` answers 400 `unsupported_token_type`. Unknown tokens, already revoked tokens and tokens of another client, when not JWT shaped, answer 200 with an empty body and no-cache headers; another client's token is left untouched. Revoking a refresh token also revokes the reference access tokens of the same subject and client. Note that the token endpoint currently issues only JWT access tokens: no production path writes the reference token store, so only tokens a host stores itself are reference tokens. Submitting a JWT shaped token (one containing a `.`) answers 400 `unsupported_token_type` and revokes nothing; the token stays valid until it expires. The JWT form is decided by the same rule access token validation uses, whatever the hint and without verifying the signature. Known limitations: a `token_type_hint` naming the wrong token type does not extend the search to the other type, as RFC 7009 §2.1 requires, so such a token is not revoked; a handle containing a `.` that a host stores itself, refresh or reference, answers 400 `unsupported_token_type` and cannot be revoked through this endpoint; with `EnableTokenRevocationEndpoint` off, a custom discovery entry named `revocation_endpoint` that a host points back at this server's revocation route still appears in the discovery document, although the endpoint answers 404. Parameters are read from the request body only.
- `results.ClientAuthenticationErrorResult` writes the `invalid_client` answer with its headers set before the status code.
- Discovery: `revocation_endpoint` is advertised again in the default assembly now that the route is registered.
- Device authorization endpoint (RFC 8628) at `POST /connect/deviceauthorization`, handled by `handlers.DeviceAuthorizationHandler` and registered through the composition root. With `EnableDeviceAuthorizationEndpoint` off it answers 404 and is not advertised. Clients authenticate as at the token endpoint; a public client sends only `client_id`. A failed client authentication answers `invalid_client` (401 with a `WWW-Authenticate` challenge when the request carries an `Authorization` header, 400 otherwise); `invalid_request`, `invalid_scope` and `unauthorized_client` answer 400 with a JSON body holding only the error code and no-cache headers, written by the new `results.DeviceAuthorizationErrorResult`. Parameters are read from the request body only. The device then polls the token endpoint with the `device_code` grant type and receives `authorization_pending`, `slow_down`, `access_denied`, `expired_token` or tokens; a device code is redeemed once. Known limitations: user codes come from `math/rand` and wicket does not rate-limit user code attempts, which is left to the host's verification page; `verification_uri_complete` does not URL-encode the user code; lookup and removal of a device code are not atomic, so concurrent polls may redeem it twice.
- `services.DeviceFlowInteractionService` for the host's verification page: `GetAuthorizationContext` returns the client, requested scopes, whether the request is OpenID Connect and the expiry for a user code; `Approve` authorizes the device for an authenticated subject (which must carry `sub`) and a subset of the requested scopes; `Deny` rejects it. Errors are reported in a fixed order through `ErrDeviceFlowUserCodeNotFound`, `ErrDeviceFlowUserCodeExpired`, `ErrDeviceFlowUserCodeAlreadyHandled` and, for `Approve`, `ErrDeviceFlowInvalidApproval`. Approval narrows the requested scopes to the approved ones, so a refresh token cannot widen the grant. No consent is remembered. Resolve it from the request scope like `services.InteractionService`.
- `storagetest`: MUST case `UpdateVisibleByDeviceCode` for `DeviceFlowStore`: after `UpdateByUserCode`, both `FindByUserCode` and `FindByDeviceCode` return the new record, including its authorization state, scopes, subject and session id.
- Discovery: `device_authorization_endpoint` and the `device_code` grant type are advertised again in the default assembly now that the route is registered.
- OpenID Connect Back-Channel Logout 1.0 delivery. When server-side sessions and the check-session endpoint are both enabled, loading the end-session callback iframe signs a logout token for every client of the ended session that registered a `BackChannelLogoutUri` and posts it as `application/x-www-form-urlencoded`. The token is typed `logout+jwt`, lives two minutes and carries `iss`, `aud`, `iat`, `nbf`, `exp`, a fresh `jti`, the back-channel logout `events` object, `sid` and the session's `sub`, never `nonce`; it follows the client's identity token signing algorithms. Before anything is sent the logout context is checked against the session store (the session must exist and be current, the subject must match, and only clients recorded for the session are notified). Posts run concurrently and the callback waits for them for at most five seconds; failing relying parties are only logged. A callback loaded more than 300 seconds after its logout context was written does not deliver again. Known limitations: delivery depends on the browser loading the callback iframe; reloading it within 300 seconds delivers again; sign-outs that bypass `/connect/endsession`, and session expiry or deletion, send nothing; logout context handles are not integrity protected by the default data protection, so a party knowing a session's `sid` can make that session's relying parties receive a logout notification; logout URIs are not filtered for internal addresses.
- Discovery: `backchannel_logout_supported` and `backchannel_logout_session_supported` are advertised when server-side sessions and the check-session endpoint are both enabled. The default assembly keeps server-side sessions off and does not advertise them.
- Identity tokens issued within a user session carry the session id as `sid`.
- Hosts that inject a back-channel logout HTTP client through `ServerConfig.SetBackChannelLogoutHttpClient` must give it a timeout: response bodies are not closed, so connections are reclaimed only by the timeout.

### Changed

- **Breaking**: `services/impl.NewBackchannelLogoutService` takes the token creation service, client store, issuer name service, session store, system clock and options, and `handlers.NewEndSessionCallbackHandler` takes the back-channel logout service, the logout context message store and the system clock. Code that builds them through the composition root needs no change.
- Signing out of the default sign-out scheme through the authentication service also clears the server-side session cookie; signing out of any other scheme leaves it.
- **Breaking**: the conformance suites `storagetest`, `sessiontest` and `keymgmttest` step `SuiteVersion` from `1.0.0` to `1.1.0` together, because `storagetest` gains the MUST case `UpdateVisibleByDeviceCode`. Hosts compare an adapter's `ConformsTo()` with `SuiteVersion` for equality, so an adapter whose credential still reads `1.0.0` is refused at assembly until it passes the 1.1.0 suites and returns `1.1.0`. Adapters maintained outside this repository need the same update.
- **Breaking**: `TokenRevocationResponse.Success` now means the token was found (false for a miss, with no error); the endpoint answers 200 either way.

### Fixed

- Server-side sessions: a session created at sign-in was never restored on later requests, because nothing loaded it from the session cookie. Identity tokens carried no `sid`, end-session found no session or participating clients, and no front-channel or back-channel logout happened. `UserSession` now restores the session once per request when its session id, client list or client registration is first needed, and adopts it only when the request's authenticated user is the session's subject; otherwise the session cookie is cleared. With server-side sessions enabled, access and identity tokens therefore carry `sid` and the end-session callback renders the front-channel iframes.
- Back-channel logout: without a host-provided HTTP client the back-channel logout client was nil, so the first delivery would panic. A default client with a five second timeout that does not follow redirects is used instead.
- Token revocation: a refresh token submitted without `token_type_hint` was not revoked, because a miss in the reference token store was reported as success and the refresh token store was never consulted. A miss in either store is reported as not found again, so the no-hint path reaches the refresh token store.
- Device flow: polling throttling never took effect, because the last poll time was written with `time.Time.String()` and read back as RFC 3339; it is now written and read as RFC 3339 with fractional seconds, so a second poll within the interval answers `slow_down`. A client without `PollingInterval` now falls back to `DeviceFlow.Interval` instead of dereferencing a nil pointer.
- Device flow options: `DeviceFlow` was left at its zero value in the default options, so the advertised `interval` was 0 and a client without `PollingInterval` was never throttled. The defaults are now applied: `Interval` is 5 seconds (RFC 8628 §3.2) and `DefaultUserCodeType` is numeric.
- Device authorization: the success response was sent as `text/plain` because the status line was written before `Content-Type`; it is now `application/json`. An empty `verification_uri_complete` is left out instead of written as an empty string.
- Device code grant: the validated scopes were never handed on, so tokens issued for a device code carried no scope or audience and no refresh token was issued. They now carry the authorized scopes, and approving `offline_access` issues a refresh token.
- In-memory device flow store: `UpdateByUserCode` replaced the record under the user code only, so polling by device code never saw the user's decision. Both lookups now return the updated record, and updating an unknown user code fails with `storage.ErrNotFound`.

## [0.2.1] - 2026-11-12

### Changed

- **Breaking**: `handlers.NewDiscoveryHandler` takes three new parameters, `endpointPaths []string`, `backChannelLogout services.BackchannelLogoutService` and `secretParsers validators.SecretsListParser`, which carry the assembly facts the discovery filter needs. Code that builds the handler through the composition root needs no change; code calling the constructor directly must pass them (a nil `endpointPaths` means no route is registered, so every endpoint URL under the base URL is withdrawn).

### Fixed

- Discovery: the configuration document now advertises only what the running assembly can serve. Endpoint URLs under the server's base URL are kept only when a route is registered for them, so `revocation_endpoint` and `device_authorization_endpoint` (no handlers yet, previously answering 404) are no longer advertised, and `device_code` is dropped from `grant_types_supported` together with the device authorization endpoint. `backchannel_logout_supported` / `backchannel_logout_session_supported` are advertised only when the back-channel logout service reports that it delivers notifications (the default service does not). `authorization_response_iss_parameter_supported` follows `EmitIssuerIdentificationResponseParameter`. Mutual TLS entries need registered tls client authentication parsers: each of `tls_client_auth` / `self_signed_tls_client_auth` is advertised only when a parser provides that method; without any such parser `tls_client_certificate_bound_access_tokens` and `mtls_endpoint_aliases` are withheld, and otherwise each alias is kept only when its primary endpoint is still advertised and, for a path-form alias (no `MutualTls.DomainName`), its path is a registered route. When `MutualTls.Enabled` is on and any mutual TLS entry is removed, a warning is logged. Host `CustomEntries` are not filtered, except under a key the generator itself writes: such a key is always filtered, including when the generator's switch for it is off and the custom value is the one in the document, so a custom entry cannot re-advertise a withdrawn capability. Lists under those keys are judged element by element whether they hold `[]string` or `[]any`, and an endpoint value that is not an absolute URL is withdrawn. Keys the generator never writes, such as `registration_endpoint`, stay with the host. Once a missing capability is implemented and registered, its advertisement returns without further changes.
- Tests: an assembly-level guard checks the default and the all-switches-on assemblies: every advertised endpoint must route to a handler (not 404), every capability advertised as `true` must map to implementation evidence, the advertised grant types and authentication methods must agree with the assembly, and every registered route other than the discovery document and the interaction callbacks must be advertised.
- Docs: README and API contracts describe device authorization, token revocation and back-channel logout delivery as not yet available, and document the discovery filtering rules.

[0.2.1]: https://github.com/gonewx/wicket/releases/tag/v0.2.1

## [0.2.0] - 2026-11-12

### Changed

- **Breaking**: the root package is now named `wicket` (previously `gois`), matching its import path `github.com/gonewx/wicket`. Code that imports the module without an alias and refers to `gois.Xxx` must switch to `wicket.Xxx` (or keep the old name with an explicit `gois "github.com/gonewx/wicket"` alias). Imports that already alias it as `wicket` need no change. Persisted data is unaffected: data-protection purpose strings keep their existing values.
- Tests: 工具链守卫新增运行期断言——比对 `runtime.Version()` 与 `mise.toml` 的 pin，关闭「声明文件全绿而实际以另一个工具链编译」这一失效模式（此前只读声明，该组合不被任何门禁捕获）。三处判别力子进程调用的工具链版本改为派生自同一 pin 来源，消除抬升时字面量静默滞后的漂移面。
- Docs: 开发指南增补三条验证纪律——工具链变更后的缓存处置、一切命令经 `mise exec` 的自查方式、判别力自证的收尾复核要求。

[0.2.0]: https://github.com/gonewx/wicket/releases/tag/v0.2.0

## [0.1.4] - 2026-08-21

### Changed

- Toolchain: `mise.toml` 的 Go 工具链 pin 由 `1.27rc1` 抬升至正式版 `1.27.0`。取精确补丁版本而非宽松 `1.27`，使每次工具链变更都是一次显式记录的改动。`go.mod` 的 `go 1.27` 语言版本 directive 不变——它是对下游模块的语言版本承诺，与不随发布分发的 `mise.toml` pin 相互独立。与该 pin 耦合的 `tests/e2e` 守卫同步更新：原先锁定「`go.mod` 无 rc 而 `mise.toml` 有 rc」这一 1.27 预发布期间的过渡态分家，现改为对两者分别精确比对（directive 等于 `1.27`、pin 等于 `1.27.0`）——预发布版本因此不可能通过，同时避免了子串匹配把他工具的 rc 版本或注释误判为 Go pin。pin 的读取限定在 `[tools]` 表内，并对无法读作单一标量的写法按名拒绝。无生产代码改动。

[0.1.4]: https://github.com/gonewx/wicket/releases/tag/v0.1.4

## [0.1.3] - 2026-08-08

### Fixed

- Claims: `ClaimsIdentity` now implements `MarshalJSON`/`UnmarshalJSON` so the
  model survives a JSON round trip. The identity's `authenticationType` and
  `claims` fields are unexported and were silently dropped by `encoding/json`,
  which made every persistence adapter lose the subject claims (and the
  authentication type) of stored authorization codes, refresh tokens, device
  codes and backchannel requests on the first Store/Get cycle. Hosts on the
  PostgreSQL adapter observe this as an access token without a `sub` claim at
  UserInfo; the fix restores it.

### Changed

- Docs: 全面刷新 `docs/` 文档集至 v0.1.2 状态——技术栈版本（jwx v3.2.0、gjson 1.19.0、uuid 1.6.0、httprc v3.0.6、godi v0.1.0）、di 装配文件改名（`dsl_*.go`）、scheme 名（`wicket` / `wicket.external`）、新增存储端口三族与契约测试套件、`wechatverify` / `phoneverify` 无状态验证包；新增根 README.md 作为发布库入口。

[0.1.3]: https://github.com/gonewx/wicket/releases/tag/v0.1.3

## [0.1.2] - 2026-08-07

Review corrections to the v0.1.1 artifacts: CI compile coverage for the
locally-executed lineage gate package, hardened package exclusion (anchored
path covering future subpackages), and documentation alignment with the
released CI shape.

### Changed

- CI workflow: the `tests/e2e` exclusion now anchors the full package path
  (including future subpackages) and fails loudly on an empty package list;
  the lineage gate package keeps compile-level coverage via `go vet` so API
  drift cannot pass CI silently.
- Docs: development guide CI section and storage persistence guide updated to
  reflect the released CI shape (lineage gates run in the local release
  window; no evidence-archive credentials in CI; internal workspace document
  references no longer shipped as links).

[0.1.2]: https://github.com/gonewx/wicket/releases/tag/v0.1.2

## [0.1.1] - 2026-08-07

Assembly container regenerated with the pinned generator release, and the CI
workflow scoped so the build/test gate set runs on CI while the tests/e2e
package (which depends on an out-of-repo private evidence archive) runs in the
local release window.

### Added

- Generic typed accessors on the assembly root: `Get[T any]() (T, bool)`
  and `GetRequired[T any]() T`.

### Changed

- Regenerated the assembly container from the pinned generator release
  (`godi-gen` at the version declared in `go.mod`).
- CI workflow: the `tests/e2e` package is excluded from the CI test run;
  those gates execute in the local release window.

[0.1.1]: https://github.com/gonewx/wicket/releases/tag/v0.1.1

## [0.1.0] - 2026-08-07

First tagged release. This version fixes the public storage port contracts, ships
conformance test suites for adapter authors, and stabilizes the hosting assembly.

### Added

- First externally consumable release, resolvable via `go get github.com/gonewx/wicket`
  on a Go 1.27 toolchain (release candidate until the 1.27.0 final ships).
- Public storage port family with context-first method signatures, sentinel errors
  for missing records, handle-based access, versioned refresh-token rotation, and
  core-side expiry semantics.
- Conformance test suites for adapter authors: `storage/storagetest`,
  `session/sessiontest`, and `keymgmt/keymgmttest`, each exporting a `SuiteVersion`
  constant with a `ConformsTo()` convention for version-verified adapters.
- Host-side store injection seams with explicit in-memory fallback declaration and
  assembly-time validation, plus a single root lifecycle for resource release.
- External IdP verification packages (Apple/Google/WeChat/phone-number) for
  stateless token validation without store dependencies.
- Adapter authoring guide covering schema derivation from port access patterns,
  design records, credential-safe logging, and lineage gate requirements.

[0.1.0]: https://github.com/gonewx/wicket/releases/tag/v0.1.0
