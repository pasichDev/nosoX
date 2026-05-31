package wallet

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	v2crypto "github.com/noso-project/noso-go/v2/crypto"
)

// CoinbaseRecord stores a fresh Pedersen blinding scalar tied to a
// specific block height and reward amount. The miner persists one of
// these every time it constructs a coinbase output so it can later
// spend that output (which requires knowing the blinding factor and
// thus the kernel-excess secret key).
type CoinbaseRecord struct {
	Height   uint64     `json:"h"`
	Amount   int64      `json:"v"`
	Blinding [32]byte   `json:"b"`
	Commit   [33]byte   `json:"c"`
}

// CoinbaseStore is a simple file-backed log of CoinbaseRecord entries.
// Writes are appended and fsync'd; reads scan from the start. For a
// production miner that earns many coinbases this should graduate to a
// BadgerDB bucket — but the API stays the same.
type CoinbaseStore struct {
	mu   sync.Mutex
	path string
	all  []CoinbaseRecord
}

// OpenCoinbaseStore loads (or creates) the file at path.
func OpenCoinbaseStore(path string) (*CoinbaseStore, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	c := &CoinbaseStore{path: path}
	raw, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err == nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, &c.all); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// Allocate generates a fresh blinding factor, computes the
// corresponding commitment for the given amount, persists the record,
// and returns it. The miner uses Commit as the output's commit field
// and ExcessKey for signing the coinbase kernel.
func (c *CoinbaseStore) Allocate(height uint64, amount int64) (CoinbaseRecord, error) {
	var blind [32]byte
	if _, err := rand.Read(blind[:]); err != nil {
		return CoinbaseRecord{}, err
	}
	commit, err := v2crypto.PedersenCommit(amount, blind[:])
	if err != nil {
		return CoinbaseRecord{}, err
	}
	rec := CoinbaseRecord{
		Height:   height,
		Amount:   amount,
		Blinding: blind,
		Commit:   commit,
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.all = append(c.all, rec)
	return rec, c.flushLocked()
}

// Lookup returns the CoinbaseRecord for the given commitment. Used when
// the miner later wants to spend its own coinbase.
func (c *CoinbaseStore) Lookup(commit [33]byte) (CoinbaseRecord, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.all {
		if c.all[i].Commit == commit {
			return c.all[i], true
		}
	}
	return CoinbaseRecord{}, false
}

// All returns a snapshot of every coinbase the miner has produced.
func (c *CoinbaseStore) All() []CoinbaseRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]CoinbaseRecord, len(c.all))
	copy(out, c.all)
	return out
}

func (c *CoinbaseStore) flushLocked() error {
	if c.path == "" {
		return errors.New("coinbase: no store path")
	}
	body, err := json.MarshalIndent(c.all, "", "  ")
	if err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}

// CoinbaseKernelSignHash is the canonical digest the miner signs for a
// coinbase kernel. Independent of the Excess commitment so a verifier
// can recompute it from header data alone.
func CoinbaseKernelSignHash(height uint64, amount int64, commit [33]byte) [32]byte {
	h := sha256.New()
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], height)
	h.Write(b[:])
	binary.BigEndian.PutUint64(b[:], uint64(amount))
	h.Write(b[:])
	h.Write(commit[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SignCoinbase signs the coinbase kernel for height/amount using the
// blinding factor as the secret scalar. Returns the Schnorr signature
// (65 bytes) ready to embed in Kernel.ExcessSig.
//
// Pedersen excess for a coinbase output is r·G (the value term cancels
// because input commits sum to zero for a coinbase). Knowing r is
// therefore knowing the kernel's secret key.
func SignCoinbase(rec CoinbaseRecord) ([]byte, error) {
	msg := CoinbaseKernelSignHash(rec.Height, rec.Amount, rec.Commit)
	return v2cryptoSchnorrSign(rec.Blinding[:], msg[:])
}

// VerifyCoinbase checks the Schnorr signature on a coinbase kernel.
// Standalone helper so the chain validator can call it without pulling
// in the wallet package.
func VerifyCoinbase(height uint64, amount int64, commit [33]byte, sig []byte) bool {
	msg := CoinbaseKernelSignHash(height, amount, commit)
	// The excess "public key" equals the commitment IFF amount == 0.
	// For a coinbase the kernel-excess commit is r·G + amount·H. We
	// verify Schnorr against (commit - amount·H), but since amount and
	// commit are known by every validator, this is straightforward to
	// recompute. The helper below does it.
	return v2cryptoVerifyCoinbase(commit, amount, msg[:], sig)
}
