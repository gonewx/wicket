# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-08-07

First tagged release. This version fixes the public storage port contracts, ships
conformance test suites for adapter authors, and stabilizes the hosting assembly.

### Added

- First externally consumable release, resolvable via `go get github.com/gonewx/wicket`.
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
