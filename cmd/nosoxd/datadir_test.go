package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pasichDev/noso-go/v2/wallet"
)

func TestPrepareDataDirCreatesPrivateTree(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "node", "data")
	if err := prepareDataDir(dir); err != nil {
		t.Fatal(err)
	}
	store, err := wallet.OpenCoinbaseStore(filepath.Join(dir, coinbaseFileName))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Allocate(1, 5); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]os.FileMode{dir: 0o700, filepath.Join(dir, coinbaseFileName): 0o600} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Errorf("%s mode %o, want %o", path, got, want)
		}
	}
}

func TestPrepareDataDirTightensExistingLooseModes(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, coinbaseFileName)
	if err := os.WriteFile(path, []byte("[]"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := prepareDataDir(dir); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]os.FileMode{dir: 0o700, path: 0o600} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != want {
			t.Errorf("%s mode %o, want %o", p, info.Mode().Perm(), want)
		}
	}
}
