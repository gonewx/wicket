// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

// Package storagetest defines an executable conformance suite for the grant
// store port family declared in package storage. The suite pins the port
// contract in runnable form: an adapter proves compliance by passing every
// MUST-graded case, and a host verifies an adapter's credential before
// assembly.
//
// # Entry points
//
// One entry point exists per store family:
//
//	RunAuthorizationCodeStoreSuite
//	RunRefreshTokenStoreSuite
//	RunReferenceTokenStoreSuite
//	RunUserConsentStoreSuite
//	RunPersistedGrantStoreSuite
//	RunDeviceFlowStoreSuite
//	RunBackchannelAuthenticationRequestStoreSuite
//
// Every entry takes a factory that must return a fresh empty store on each
// call; the suite calls the factory before every case so no state leaks
// between cases. The factory may open connections, run migrations, or set up
// fixtures as the adapter requires; the suite never inspects the backing
// medium.
//
// # Grading
//
// Cases are graded MUST or MAY following RFC 2119 usage. MUST cases run
// unconditionally; an adapter that skips or fails a MUST case cannot claim
// compliance. MAY cases cover enhanced behavior; they are skipped by default
// and enabled with WithMay(true).
//
// # Compliance credential
//
// SuiteVersion identifies the contract version this suite verifies. A
// compliant adapter exposes ConformsTo() string returning the suite version
// it was verified against; a host compares adapter.ConformsTo() to
// SuiteVersion at assembly time and refuses to assemble an adapter whose
// credential does not match. An adapter without the method carries no
// credential and must not be called compliant.
package storagetest
