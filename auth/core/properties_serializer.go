// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package core

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/gonewx/wicket/auth"
)

const (
	PropertiesSerializerFormatVersion int32 = 1
)

type PropertiesSerializer struct {
}

func NewPropertiesSerializer() *PropertiesSerializer {
	return &PropertiesSerializer{}
}

func (s *PropertiesSerializer) Serialize(model *auth.Properties) []byte {
	var b bytes.Buffer
	WriteProperties(&b, model)
	return b.Bytes()

}
func (s *PropertiesSerializer) Deserialize(data []byte) *auth.Properties {
	b := bytes.NewBuffer(data)
	return ReadProperties(b)
}

func WriteProperties(w io.Writer, properties *auth.Properties) {
	_ = binary.Write(w, binary.BigEndian, PropertiesSerializerFormatVersion)

	var count int32
	count = int32(len(properties.Items))
	_ = binary.Write(w, binary.BigEndian, count)

	for key, value := range properties.Items {
		var length int32
		length = int32(len(key))
		_ = binary.Write(w, binary.BigEndian, length)
		_, _ = w.Write([]byte(key))

		length = int32(len(value))
		_ = binary.Write(w, binary.BigEndian, length)
		_, _ = w.Write([]byte(value))
	}
}

func ReadProperties(reader io.Reader) *auth.Properties {

	var version int32
	err := binary.Read(reader, binary.BigEndian, &version)
	if err != nil || version != PropertiesSerializerFormatVersion {
		return nil
	}

	var count int32
	err = binary.Read(reader, binary.BigEndian, &count)
	if err != nil {
		return nil
	}

	extra := make(map[string]string, 0)

	var index int32
	for index != count {
		index++
		var length int32
		err = binary.Read(reader, binary.BigEndian, &length)
		if err != nil {
			return nil
		}
		key := make([]byte, length)
		_, _ = reader.Read(key)
		err = binary.Read(reader, binary.BigEndian, &length)
		if err != nil {
			return nil
		}
		value := make([]byte, length)
		_, _ = reader.Read(value)
		extra[string(key)] = string(value)
	}
	properties := auth.NewProperties()
	properties.Items = extra

	return properties
}
