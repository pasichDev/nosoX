package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

const coinbaseFileName = "coinbases.json"

// prepareDataDir creates the data directory and makes sure the miner's secret
// file lives behind owner-only permissions. coinbases.json holds the blinding
// factor, i.e. the spending key, of every coinbase output in plaintext.
//
//   - A missing directory is created 0700.
//   - An existing directory that group or others can access is tightened to
//     0700, because it is the parent of the secret file. A directory we cannot
//     tighten is a startup error.
//   - An existing coinbases.json with group/other bits is tightened to 0600.
//     Files the store writes are already created 0600.
func prepareDataDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("not a directory")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 { // Windows has no Unix mode bits (ACLs apply)
		if err := os.Chmod(dir, 0o700); err != nil {
			return fmt.Errorf("data directory is accessible to other users and cannot be restricted: %w", err)
		}
	}
	path := filepath.Join(dir, coinbaseFileName)
	finfo, err := os.Lstat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil
	case err != nil:
		return err
	case !finfo.Mode().IsRegular():
		return fmt.Errorf("%s is not a regular file", coinbaseFileName)
	case runtime.GOOS != "windows" && finfo.Mode().Perm()&0o077 != 0:
		return os.Chmod(path, 0o600)
	}
	return nil
}
