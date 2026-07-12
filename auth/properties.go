// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package auth

import (
	"encoding/json"
	"time"
)

// Reserved Items keys carrying typed authentication properties. The key names
// and their encodings are an established interoperability convention with the
// wider authentication ecosystem and are recorded verbatim.
const (
	persistentKey = ".persistent"
	redirectKey   = ".redirect"
	issuedKey     = ".issued"
	expiresKey    = ".expires"
	refreshKey    = ".refresh"
)

// Parameters returns the in-process parameter set, allocating it on first use so
// a zero-value or field-injected Properties still exposes a non-nil, empty set.
// The parameter set is never serialized.
func (p *Properties) Parameters() map[string]any {
	if p.parameters == nil {
		p.parameters = map[string]any{}
	}
	return p.parameters
}

// items lazily allocates the serializable Items map so writes are safe on a
// zero-value Properties.
func (p *Properties) items() map[string]string {
	if p.Items == nil {
		p.Items = map[string]string{}
	}
	return p.Items
}

// GetString reads a serializable string entry. A missing key returns nil; an
// empty string is a legitimate stored value and returns a pointer to it.
func (p *Properties) GetString(key string) *string {
	if p.Items == nil {
		return nil
	}
	value, ok := p.Items[key]
	if !ok {
		return nil
	}
	return &value
}

// SetString writes a serializable string entry. A nil value removes the entry;
// removing an absent key is a no-op. An empty string is stored as-is.
func (p *Properties) SetString(key string, value *string) {
	if value == nil {
		delete(p.Items, key)
		return
	}
	p.items()[key] = *value
}

// GetParameter reads an in-process parameter. A missing key returns nil.
func (p *Properties) GetParameter(key string) any {
	if p.parameters == nil {
		return nil
	}
	return p.parameters[key]
}

// SetParameter writes an in-process parameter. A nil value keeps the key with a
// nil value rather than removing it, distinguishing "present but unset" from
// "absent"; any other value is stored by reference.
func (p *Properties) SetParameter(key string, value any) {
	p.Parameters()[key] = value
}

// GetDateTime decodes a reserved time entry from its RFC1123 UTC text. A missing
// key or malformed text returns nil and leaves the stored text untouched.
func (p *Properties) GetDateTime(key string) *time.Time {
	value := p.GetString(key)
	if value == nil {
		return nil
	}
	parsed, err := time.Parse(time.RFC1123, *value)
	if err != nil {
		return nil
	}
	return &parsed
}

// SetDateTime encodes a time as RFC1123 UTC text. A nil value removes the entry.
func (p *Properties) SetDateTime(key string, value *time.Time) {
	if value == nil {
		delete(p.Items, key)
		return
	}
	encoded := value.UTC().Format(time.RFC1123)
	p.items()[key] = encoded
}

// GetBool decodes a reserved boolean entry. Only "true"/"false" decode; a
// missing key, empty string, or malformed text returns nil and leaves the stored
// text untouched.
func (p *Properties) GetBool(key string) *bool {
	value := p.GetString(key)
	if value == nil {
		return nil
	}
	switch *value {
	case "true":
		result := true
		return &result
	case "false":
		result := false
		return &result
	default:
		return nil
	}
}

// SetBool encodes a boolean as "true"/"false". A nil value removes the entry.
func (p *Properties) SetBool(key string, value *bool) {
	if value == nil {
		delete(p.Items, key)
		return
	}
	text := "false"
	if *value {
		text = "true"
	}
	p.items()[key] = text
}

// IsPersistent reports whether the persistence marker is present.
func (p *Properties) IsPersistent() bool {
	if p.Items == nil {
		return false
	}
	_, ok := p.Items[persistentKey]
	return ok
}

// SetIsPersistent toggles the persistence marker: true stores the reserved key
// with an empty-string value, false removes it.
func (p *Properties) SetIsPersistent(value bool) {
	if value {
		p.items()[persistentKey] = ""
		return
	}
	delete(p.Items, persistentKey)
}

// RedirectUri returns the stored redirect target, or nil when unset.
func (p *Properties) RedirectUri() *string { return p.GetString(redirectKey) }

// SetRedirectUri stores the redirect target verbatim; nil removes it.
func (p *Properties) SetRedirectUri(value *string) { p.SetString(redirectKey, value) }

// Issued returns the issued timestamp, or nil when unset.
func (p *Properties) Issued() *time.Time { return p.GetDateTime(issuedKey) }

// SetIssued stores the issued timestamp; nil removes it.
func (p *Properties) SetIssued(value *time.Time) { p.SetDateTime(issuedKey, value) }

// Expires returns the expiry timestamp, or nil when unset.
func (p *Properties) Expires() *time.Time { return p.GetDateTime(expiresKey) }

// SetExpires stores the expiry timestamp; nil removes it.
func (p *Properties) SetExpires(value *time.Time) { p.SetDateTime(expiresKey, value) }

// AllowRefresh returns the refresh flag, or nil when unset.
func (p *Properties) AllowRefresh() *bool { return p.GetBool(refreshKey) }

// SetAllowRefresh stores the refresh flag; nil removes it.
func (p *Properties) SetAllowRefresh(value *bool) { p.SetBool(refreshKey, value) }

// Clone produces an independent copy: later structural changes to the source's
// Items or parameter set do not affect the copy.
func (p *Properties) Clone() *Properties {
	clone := &Properties{
		Items:      make(map[string]string, len(p.Items)),
		parameters: make(map[string]any, len(p.parameters)),
	}
	for key, value := range p.Items {
		clone.Items[key] = value
	}
	for key, value := range p.parameters {
		clone.parameters[key] = value
	}
	return clone
}

// MarshalJSON serializes only the Items layer; the in-process parameter set is
// never emitted. Map keys are ordered by encoding/json.
func (p *Properties) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Items map[string]string
	}{Items: p.Items})
}

// UnmarshalJSON restores the Items layer and resets the parameter set to a
// non-nil empty set. Any parameter field present in the raw payload is ignored.
func (p *Properties) UnmarshalJSON(data []byte) error {
	var raw struct {
		Items map[string]string
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw.Items == nil {
		raw.Items = map[string]string{}
	}
	p.Items = raw.Items
	p.parameters = map[string]any{}
	return nil
}
