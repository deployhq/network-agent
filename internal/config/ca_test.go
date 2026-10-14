package config_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/deployhq/network-agent/internal/config"
	"github.com/deployhq/network-agent/internal/testca"
)

func TestCACertDefaultsToTheEmbeddedBundle(t *testing.T) {
	t.Setenv(config.CAFileEnv, "")

	embedded := testca.Bundle(testca.New(t, "embedded"))
	got, err := config.CACert(embedded)
	if err != nil {
		t.Fatalf("CACert: %v", err)
	}
	if !bytes.Equal(got, embedded) {
		t.Error("CACert did not return the embedded bundle")
	}
}

func TestCACertReadsTheOverrideFile(t *testing.T) {
	embedded := testca.Bundle(testca.New(t, "embedded"))
	override := testca.Bundle(testca.New(t, "operator supplied"))

	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, override, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(config.CAFileEnv, path)

	got, err := config.CACert(embedded)
	if err != nil {
		t.Fatalf("CACert: %v", err)
	}
	if !bytes.Equal(got, override) {
		t.Error("CACert did not return the override file's contents")
	}
	if bytes.Equal(got, embedded) {
		t.Error("CACert returned the embedded bundle despite the override")
	}
}

// TestCACertFailsRatherThanFallingBack: silently trusting a different CA than
// the operator asked for is worse than refusing to start, so an unusable
// override must be an error and never a fallback to the embedded bundle.
func TestCACertFailsRatherThanFallingBack(t *testing.T) {
	embedded := testca.Bundle(testca.New(t, "embedded"))
	dir := t.TempDir()

	empty := filepath.Join(dir, "empty.pem")
	if err := os.WriteFile(empty, nil, 0600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		path string
	}{
		{"missing file", filepath.Join(dir, "does-not-exist.pem")},
		{"a directory", dir},
		{"empty file", empty},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(config.CAFileEnv, tt.path)

			got, err := config.CACert(embedded)
			if err == nil {
				t.Fatal("expected an error, got none")
			}
			if got != nil {
				t.Error("CACert returned a bundle alongside an error")
			}
			t.Logf("rejected: %v", err)
		})
	}
}
