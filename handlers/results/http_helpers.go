// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package results

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gonewx/wicket"
	config_options "github.com/gonewx/wicket/config/options"
)

func HttpRespSetNoCache(w http.ResponseWriter) {
	w.Header().Add("Cache-Control", "no-store")
	w.Header().Add("Cache-Control", "no-cache")
	w.Header().Add("Cache-Control", "max-age=0")
	w.Header().Set("Pragma", "no-cache")
}

func HttpRespSetCache(w http.ResponseWriter, maxAge int, vary string) {
	w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", maxAge))
	if vary != "" {
		w.Header().Set("Vary", vary)
	}
}

func HttpRespWriteJson(w http.ResponseWriter, value any, contentType string) error {
	if contentType == "" {
		contentType = "application/json"
	}
	w.Header().Set("Content-Type", contentType)
	return json.NewEncoder(w).Encode(value)
}

func HttpRespWriteHtml(w http.ResponseWriter, value []byte, contentType string) error {
	if contentType == "" {
		contentType = "text/html; charset=utf-8"
	}
	w.Header().Set("Content-Type", contentType)
	_, err := w.Write(value)
	return err
}

func AddScriptCspHeaders(w http.ResponseWriter, options *config_options.CspOptions, hashes ...string) {
	directives := []string{"default-src 'none'"}
	if len(hashes) > 0 && hashes[0] != "" {
		sources := hashes
		if options != nil && options.Level == gois.CspLevelOne {
			// CSP Level 1 browsers do not recognise hash-sources and would block the
			// inline script; 'unsafe-inline' is the backward-compatible fallback. CSP2+
			// browsers ignore 'unsafe-inline' when a hash is present (W3C CSP).
			sources = append([]string{"unsafe-inline"}, hashes...)
		}
		directives = append(directives, "script-src '"+strings.Join(sources, "' '")+"'")
	}
	addCsp(w, options, directives)
}

func AddStyleCspHeaders(w http.ResponseWriter, options *config_options.CspOptions, hash string, frameSrc string) {
	directives := []string{"default-src 'none'"}
	if hash != "" {
		styleSrc := "'" + hash + "'"
		if options != nil && options.Level == gois.CspLevelOne {
			styleSrc = "'unsafe-inline' " + styleSrc
		}
		directives = append(directives, "style-src "+styleSrc)
	}
	if frameSrc != "" {
		directives = append(directives, "frame-src "+frameSrc)
	}
	addCsp(w, options, directives)
}

func addCsp(w http.ResponseWriter, options *config_options.CspOptions, directives []string) {
	value := strings.Join(directives, "; ")
	w.Header().Set("Content-Security-Policy", value)
	if options == nil || options.AddDeprecatedHeader {
		w.Header().Set("X-Content-Security-Policy", value)
	}
}
