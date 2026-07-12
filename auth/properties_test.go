// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package auth

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func strPtr(s string) *string        { return &s }
func boolPtr(b bool) *bool           { return &b }
func intPtr(i int) *int              { return &i }
func timePtr(t time.Time) *time.Time { return &t }

func TestPropertiesItemsReuseInjectedReference(t *testing.T) {
	t.Parallel()

	injected := map[string]string{"foo": "bar"}
	properties := &Properties{Items: injected}

	require.Equal(t, injected, properties.Items)

	// A mutation through the original map is visible via the property object,
	// proving both sides share the same underlying reference rather than a copy.
	injected["baz"] = "quux"
	require.Equal(t, "quux", properties.Items["baz"])
}

func TestPropertiesDefaultConstructionIsEmpty(t *testing.T) {
	t.Parallel()

	properties := NewProperties()

	require.NotNil(t, properties.Items)
	require.Empty(t, properties.Items)
	require.NotNil(t, properties.parameters)
	require.Empty(t, properties.parameters)
}

func TestPropertiesParameterSetIsNonNilEmptyOnInjectedItems(t *testing.T) {
	t.Parallel()

	properties := &Properties{Items: map[string]string{"foo": "bar"}}

	require.NotNil(t, properties.Parameters())
	require.Empty(t, properties.Parameters())
}

func TestPropertiesBothCollectionsReuseInjectedReferences(t *testing.T) {
	t.Parallel()

	items := map[string]string{"foo": "bar"}
	parameters := map[string]any{"count": 7, "names": []string{"a", "b"}}
	properties := &Properties{Items: items, parameters: parameters}

	require.Equal(t, items, properties.Items)
	require.Equal(t, parameters, properties.Parameters())

	items["added"] = "later"
	parameters["late"] = []string{"c"}
	require.Equal(t, "later", properties.Items["added"])
	require.Equal(t, []string{"c"}, properties.Parameters()["late"])
}

func TestPropertiesCloneIsDeepCopy(t *testing.T) {
	t.Parallel()

	original := NewProperties()
	original.Items["foo"] = "bar"
	original.SetParameter("baz", "quux")

	clone := original.Clone()

	// Structural changes to the source after cloning must not reach the copy.
	original.Items["foo"] = "changed"
	original.Items["new"] = "entry"
	original.SetParameter("baz", "changed")
	original.SetParameter("new", "param")

	require.Equal(t, "bar", clone.Items["foo"])
	require.NotContains(t, clone.Items, "new")
	require.Equal(t, "quux", clone.Parameters()["baz"])
	require.NotContains(t, clone.Parameters(), "new")
	require.NotEqual(t, original.Items, clone.Items)
	require.NotEqual(t, original.Parameters(), clone.Parameters())
}

func TestPropertiesStringEntryAccess(t *testing.T) {
	t.Parallel()

	properties := NewProperties()

	// Reading a missing key returns nil.
	require.Nil(t, properties.GetString("missing"))

	// Writing a new key adds one entry.
	properties.SetString("k", strPtr("v"))
	require.Equal(t, "v", *properties.GetString("k"))
	require.Len(t, properties.Items, 1)

	// Overwriting the same key does not add an entry.
	properties.SetString("k", strPtr("v2"))
	require.Equal(t, "v2", *properties.GetString("k"))
	require.Len(t, properties.Items, 1)

	// An empty string is a legitimate value.
	properties.SetString("empty", strPtr(""))
	require.NotNil(t, properties.GetString("empty"))
	require.Equal(t, "", *properties.GetString("empty"))
	require.Len(t, properties.Items, 2)

	// Writing nil removes the entry.
	properties.SetString("k", nil)
	require.Nil(t, properties.GetString("k"))
	require.Len(t, properties.Items, 1)

	// Writing nil to an absent key has no side effect.
	properties.SetString("never", nil)
	require.Len(t, properties.Items, 1)
}

func TestPropertiesParameterAccess(t *testing.T) {
	t.Parallel()

	names := []string{"a", "b", "c"}
	steps := map[string]struct {
		value any
	}{
		"string pointer": {value: strPtr("v")},
		"int pointer":    {value: intPtr(123)},
		"slice":          {value: names},
	}

	for name, step := range steps {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			properties := NewProperties()

			// Reading a missing key returns nil.
			require.Nil(t, properties.GetParameter("p"))

			// Writing then reading returns the same value.
			properties.SetParameter("p", step.value)
			require.Equal(t, step.value, properties.GetParameter("p"))
			require.Len(t, properties.Parameters(), 1)

			// Writing nil keeps the key with a nil value.
			properties.SetParameter("p", nil)
			require.Nil(t, properties.GetParameter("p"))
			require.Len(t, properties.Parameters(), 1)
			_, present := properties.Parameters()["p"]
			require.True(t, present)
		})
	}
}

func TestPropertiesIsPersistent(t *testing.T) {
	t.Parallel()

	properties := NewProperties()

	// Default is non-persistent.
	require.False(t, properties.IsPersistent())

	// Setting false keeps it non-persistent and adds no entry.
	properties.SetIsPersistent(false)
	require.False(t, properties.IsPersistent())
	require.Empty(t, properties.Items)

	// Setting true adds the reserved key with an empty-string value.
	properties.SetIsPersistent(true)
	require.True(t, properties.IsPersistent())
	value, ok := properties.Items[persistentKey]
	require.True(t, ok)
	require.Equal(t, "", value)

	// Removing the entry restores non-persistent.
	properties.SetIsPersistent(false)
	require.False(t, properties.IsPersistent())
	require.NotContains(t, properties.Items, persistentKey)
}

func TestPropertiesRedirectUri(t *testing.T) {
	t.Parallel()

	properties := NewProperties()

	require.Nil(t, properties.RedirectUri())

	properties.SetRedirectUri(strPtr("/foo/bar"))
	require.Equal(t, "/foo/bar", *properties.RedirectUri())
	require.Equal(t, "/foo/bar", properties.Items[redirectKey])

	properties.SetRedirectUri(nil)
	require.Nil(t, properties.RedirectUri())
	require.NotContains(t, properties.Items, redirectKey)
}

func TestPropertiesIssued(t *testing.T) {
	t.Parallel()

	properties := NewProperties()
	issued := time.Date(2018, time.March, 21, 0, 0, 0, 0, time.UTC)

	require.Nil(t, properties.Issued())

	properties.SetIssued(timePtr(issued))
	require.True(t, issued.Equal(*properties.Issued()))
	require.Equal(t, "Wed, 21 Mar 2018 00:00:00 UTC", properties.Items[issuedKey])

	properties.SetIssued(nil)
	require.Nil(t, properties.Issued())
	require.NotContains(t, properties.Items, issuedKey)
}

func TestPropertiesExpires(t *testing.T) {
	t.Parallel()

	properties := NewProperties()
	expires := time.Date(2018, time.March, 19, 12, 34, 56, 0, time.UTC)

	require.Nil(t, properties.Expires())

	properties.SetExpires(timePtr(expires))
	require.True(t, expires.Equal(*properties.Expires()))
	require.Equal(t, "Mon, 19 Mar 2018 12:34:56 UTC", properties.Items[expiresKey])

	properties.SetExpires(nil)
	require.Nil(t, properties.Expires())
	require.NotContains(t, properties.Items, expiresKey)
}

func TestPropertiesAllowRefresh(t *testing.T) {
	t.Parallel()

	properties := NewProperties()

	require.Nil(t, properties.AllowRefresh())

	properties.SetAllowRefresh(boolPtr(true))
	require.NotNil(t, properties.AllowRefresh())
	require.True(t, *properties.AllowRefresh())
	require.Equal(t, "true", properties.Items[refreshKey])

	properties.SetAllowRefresh(boolPtr(false))
	require.NotNil(t, properties.AllowRefresh())
	require.False(t, *properties.AllowRefresh())
	require.Equal(t, "false", properties.Items[refreshKey])

	properties.SetAllowRefresh(nil)
	require.Nil(t, properties.AllowRefresh())
	require.NotContains(t, properties.Items, refreshKey)
}

func TestPropertiesDateTimeEntryEncoding(t *testing.T) {
	t.Parallel()

	properties := NewProperties()
	moment := time.Date(2018, time.March, 21, 0, 0, 0, 0, time.UTC)

	properties.SetDateTime("k", timePtr(moment))
	require.Equal(t, "Wed, 21 Mar 2018 00:00:00 UTC", properties.Items["k"])

	properties.SetDateTime("k", nil)
	require.NotContains(t, properties.Items, "k")

	properties.SetDateTime("never", nil)
	require.NotContains(t, properties.Items, "never")
}

func TestPropertiesDateTimeEntryDecoding(t *testing.T) {
	t.Parallel()

	properties := NewProperties()
	properties.Items["good"] = "Wed, 21 Mar 2018 00:00:00 UTC"
	properties.Items["bad"] = "BAR"

	decoded := properties.GetDateTime("good")
	require.NotNil(t, decoded)
	require.True(t, time.Date(2018, time.March, 21, 0, 0, 0, 0, time.UTC).Equal(*decoded))

	require.Nil(t, properties.GetDateTime("missing"))

	require.Nil(t, properties.GetDateTime("bad"))
	require.Equal(t, "BAR", properties.Items["bad"])
}

func TestPropertiesBoolEntryEncoding(t *testing.T) {
	t.Parallel()

	properties := NewProperties()

	properties.SetBool("k", boolPtr(true))
	require.Equal(t, "true", properties.Items["k"])

	properties.SetBool("k", boolPtr(false))
	require.Equal(t, "false", properties.Items["k"])

	properties.SetBool("k", nil)
	require.NotContains(t, properties.Items, "k")
}

func TestPropertiesBoolEntryDecoding(t *testing.T) {
	t.Parallel()

	properties := NewProperties()
	properties.Items["yes"] = "true"
	properties.Items["no"] = "false"
	properties.Items["empty"] = ""
	properties.Items["bad"] = "BAR"

	require.True(t, *properties.GetBool("yes"))
	require.False(t, *properties.GetBool("no"))
	require.Nil(t, properties.GetBool("missing"))

	require.Nil(t, properties.GetBool("empty"))
	require.Equal(t, "", properties.Items["empty"])

	require.Nil(t, properties.GetBool("bad"))
	require.Equal(t, "BAR", properties.Items["bad"])
}

// fullyPopulatedProperties builds the P18/P20 fixture: all five typed properties
// set plus one plain Items entry and one parameter entry.
func fullyPopulatedProperties(t *testing.T) *Properties {
	t.Helper()
	properties := NewProperties()
	properties.SetAllowRefresh(boolPtr(true))
	properties.SetExpires(timePtr(time.Date(2021, time.March, 28, 13, 47, 0, 0, time.UTC)))
	properties.SetIssued(timePtr(time.Date(2021, time.March, 28, 12, 47, 0, 0, time.UTC)))
	properties.SetIsPersistent(true)
	properties.SetRedirectUri(strPtr("/foo/bar"))
	properties.Items["foo"] = "bar"
	properties.SetParameter("baz", "quux")
	return properties
}

func TestPropertiesJSONRoundTripDropsParameters(t *testing.T) {
	t.Parallel()

	original := fullyPopulatedProperties(t)

	encoded, err := json.Marshal(original)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "baz")
	require.NotContains(t, string(encoded), "quux")

	restored := NewProperties()
	require.NoError(t, json.Unmarshal(encoded, restored))

	require.True(t, *original.AllowRefresh() == *restored.AllowRefresh())
	require.True(t, original.Expires().Equal(*restored.Expires()))
	require.True(t, original.Issued().Equal(*restored.Issued()))
	require.Equal(t, original.IsPersistent(), restored.IsPersistent())
	require.Equal(t, *original.RedirectUri(), *restored.RedirectUri())
	require.Equal(t, "bar", restored.Items["foo"])

	require.NotNil(t, restored.Parameters())
	require.Empty(t, restored.Parameters())
}

func TestPropertiesUnmarshalIgnoresParametersField(t *testing.T) {
	t.Parallel()

	restored := NewProperties()
	require.NoError(t, restored.UnmarshalJSON([]byte(`{"Parameters":{"baz":"quux"}}`)))

	require.NotNil(t, restored.Parameters())
	require.Empty(t, restored.Parameters())
}

func TestPropertiesSerializationIsMinimalAndOrdered(t *testing.T) {
	t.Parallel()

	properties := fullyPopulatedProperties(t)

	encoded, err := json.MarshalIndent(properties, "", "\t")
	require.NoError(t, err)

	want := "{\n" +
		"\t\"Items\": {\n" +
		"\t\t\".expires\": \"Sun, 28 Mar 2021 13:47:00 UTC\",\n" +
		"\t\t\".issued\": \"Sun, 28 Mar 2021 12:47:00 UTC\",\n" +
		"\t\t\".persistent\": \"\",\n" +
		"\t\t\".redirect\": \"/foo/bar\",\n" +
		"\t\t\".refresh\": \"true\",\n" +
		"\t\t\"foo\": \"bar\"\n" +
		"\t}\n" +
		"}"
	require.Equal(t, want, string(encoded))
}
