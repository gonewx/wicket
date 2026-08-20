# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
