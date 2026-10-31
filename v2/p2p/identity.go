package p2p

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"

	"github.com/libp2p/go-libp2p/core/crypto"
)

// IdentityFile is the node key inside the data directory.
const IdentityFile = "p2p_identity.key"

// looseMode reports whether a key file's mode lets other users read it. Windows
// does not keep Unix permission bits: Go reports 0666 (or 0444) for every file
// there, so the check would fail on every second start. Access on Windows is
// governed by the ACL the file inherits from the data directory (create it under
// the user's profile, as the default does); the check is skipped.
func looseMode(goos string, mode fs.FileMode) bool {
	return goos != "windows" && mode.Perm()&0o077 != 0
}

// LoadOrCreateIdentity returns the node's persistent libp2p key from dir,
// creating it (Ed25519, mode 0600) on first use. A stable key keeps the peer ID,
// and so every published /p2p/<id> seed address, valid across restarts. An
// existing key readable by group or others is refused rather than trusted.
func LoadOrCreateIdentity(dir string) (crypto.PrivKey, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("p2p: identity dir: %w", err)
	}
	path := filepath.Join(dir, IdentityFile)
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		fi, serr := os.Stat(path)
		if serr != nil {
			return nil, serr
		}
		if looseMode(runtime.GOOS, fi.Mode()) {
			return nil, fmt.Errorf("p2p: %s is accessible by others (mode %o); chmod 600 it", path, fi.Mode().Perm())
		}
		return crypto.UnmarshalPrivateKey(raw)
	case !errors.Is(err, os.ErrNotExist):
		return nil, err
	}
	key, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		return nil, err
	}
	raw, err = crypto.MarshalPrivateKey(key)
	if err != nil {
		return nil, err
	}
	// Write to a private temp file, then link into place so the key is never
	// visible with loose permissions or half written.
	tmp, err := os.CreateTemp(dir, ".identity-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return nil, err
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	if err := os.Link(tmp.Name(), path); err != nil {
		if errors.Is(err, os.ErrExist) { // lost a race with another start
			return LoadOrCreateIdentity(dir)
		}
		return nil, err
	}
	return key, nil
}
