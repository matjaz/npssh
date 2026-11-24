package main

import (
	"os"
	"path/filepath"
	"testing"
)

// A Homebrew layout: the launchd agent must point at opt/ (stable across
// upgrades), never at the versioned Cellar path that `brew upgrade` deletes.
func TestStablePathPrefersHomebrewOpt(t *testing.T) {
	prefix, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cellarBin := filepath.Join(prefix, "Cellar", "npssh", "0.1.0", "bin")
	if err := os.MkdirAll(cellarBin, 0o755); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(cellarBin, "npssh")
	if err := os.WriteFile(exe, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(prefix, "opt"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..", "Cellar", "npssh", "0.1.0"), filepath.Join(prefix, "opt", "npssh")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(prefix, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(prefix, "bin", "npssh")
	if err := os.Symlink(exe, link); err != nil {
		t.Fatal(err)
	}

	want := filepath.Join(prefix, "opt", "npssh", "bin", "npssh")
	for _, in := range []string{exe, link} {
		if got := stablePath(in); got != want {
			t.Errorf("stablePath(%s) = %s, want %s", in, got, want)
		}
	}
}

func TestStablePathOutsideHomebrew(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, "npssh")
	if err := os.WriteFile(exe, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := stablePath(exe); got != exe {
		t.Errorf("stablePath(%s) = %s, want it unchanged", exe, got)
	}
}
