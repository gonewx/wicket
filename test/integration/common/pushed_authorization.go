// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package common

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"sync"
	"time"

	"github.com/gonewx/wicket/dp"
	"github.com/gonewx/wicket/pushedauth"
	storage_memory "github.com/gonewx/wicket/storage/memory"
)

// PushedAuthorizationProtection is an authenticated data protection
// provider for pushed authorization tests: every purpose derives its own
// AES-GCM key from a fixed test key, and a protected value that was changed
// fails to unprotect. The nonce is derived from the plaintext, which keeps
// the provider free of a random source; it is a test provider only.
type PushedAuthorizationProtection struct {
	key []byte
}

// NewPushedAuthorizationProtection returns the test provider.
func NewPushedAuthorizationProtection() *PushedAuthorizationProtection {
	sum := sha256.Sum256([]byte("wicket integration pushed authorization protection"))
	return &PushedAuthorizationProtection{key: sum[:]}
}

func (p *PushedAuthorizationProtection) Create(purpose string) dp.DataProtector {
	mac := hmac.New(sha256.New, p.key)
	mac.Write([]byte(purpose))
	return &PushedAuthorizationProtection{key: mac.Sum(nil)}
}

func (p *PushedAuthorizationProtection) aead() cipher.AEAD {
	block, err := aes.NewCipher(p.key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return aead
}

func (p *PushedAuthorizationProtection) Protect(data []byte) []byte {
	aead := p.aead()
	mac := hmac.New(sha256.New, p.key)
	mac.Write(data)
	nonce := mac.Sum(nil)[:aead.NonceSize()]
	return aead.Seal(append([]byte(nil), nonce...), nonce, data, nil)
}

func (p *PushedAuthorizationProtection) Unprotect(data []byte) ([]byte, error) {
	aead := p.aead()
	if len(data) < aead.NonceSize() {
		return nil, errors.New("protected value too short")
	}
	return aead.Open(nil, data[:aead.NonceSize()], data[aead.NonceSize():], nil)
}

// AdjustableClock is a clock a test moves forward by hand.
type AdjustableClock struct {
	mu  sync.Mutex
	now time.Time
}

// NewAdjustableClock returns a clock standing at now.
func NewAdjustableClock(now time.Time) *AdjustableClock {
	return &AdjustableClock{now: now}
}

func (c *AdjustableClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves the clock forward by d.
func (c *AdjustableClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// EnablePushedAuthorization enables pushed authorization requests on the
// pipeline with an in-memory store and the test protection provider. It
// must be called before Initialize and returns the store.
func (p *WicketPipeline) EnablePushedAuthorization(options pushedauth.Options) *storage_memory.MemoryPushedAuthorizationRequestStore {
	store := storage_memory.NewMemoryPushedAuthorizationRequestStore()
	cfg := p.Root.ServerConfig()
	cfg.SetPushedAuthorizationRequestStore(store)
	cfg.SetPushedAuthorizationDataProtectionProvider(NewPushedAuthorizationProtection())
	cfg.EnablePushedAuthorizationRequests(options)
	return store
}
