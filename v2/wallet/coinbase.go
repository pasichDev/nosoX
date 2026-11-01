package wallet

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	v2crypto "github.com/pasichDev/nosoX/v2/crypto"
)

// CoinbaseRecord stores a fresh Pedersen blinding scalar tied to a
// specific block height and coinbase amount (the block reward plus the fees of
// the transactions in that block). The miner persists one of
// these every time it constructs a coinbase output so it can later
// spend that output (which requires knowing the blinding factor and
// thus the kernel-excess secret key).
type CoinbaseRecord struct {
	Height   uint64   `json:"h"`
	Amount   int64    `json:"v"`
	Blinding [32]byte `json:"b"`
	Commit   [33]byte `json:"c"`
}

// CoinbaseStore is a simple file-backed log of CoinbaseRecord entries.
// Writes replace a complete JSON snapshot and sync file/directory; reads load it. For a
// production miner that earns many coinbases this should graduate to a
// BadgerDB bucket — but the API stays the same.
type CoinbaseStore struct {
	mu   sync.Mutex
	path string
	all  []CoinbaseRecord
	// dirSyncPending: a rotation renamed the live file but making the rename
	// durable failed. The keys are safe in the archive; the next Persist retries
	// the sync before it writes a new live file.
	dirSyncPending bool
}

// OpenCoinbaseStore loads (or creates) the file at path.
func OpenCoinbaseStore(path string) (*CoinbaseStore, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	c := &CoinbaseStore{path: path}
	raw, err := readBoundedSecret(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err == nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, &c.all); err != nil {
			return nil, err
		}
	}
	if len(c.all) > MaxCoinbaseRecords {
		return nil, errors.New("coinbase: too many records")
	}
	seen := make(map[[33]byte]bool, len(c.all))
	for _, rec := range c.all {
		want, err := v2crypto.PedersenCommit(rec.Amount, rec.Blinding[:])
		if err != nil || want != rec.Commit || !v2crypto.ValidPublicPoint(rec.Commit) || seen[rec.Commit] {
			return nil, errors.New("coinbase: inconsistent record")
		}
		seen[rec.Commit] = true
	}
	return c, nil
}

// MaxCoinbaseRecords bounds the records one file may hold (and one import may
// read). When a file reaches CoinbaseRotateRecords the store archives it intact
// beside itself and continues in a fresh file, so mining never stops and no key
// is deleted.
const (
	MaxCoinbaseRecords    = 10000
	CoinbaseRotateRecords = 5000
)

// NewRecord generates a fresh blinding factor and the commitment for amount
// WITHOUT persisting anything. A miner holds the record in memory while it
// grinds a candidate and calls Persist only for a block it actually solved,
// before the block is added or gossiped.
func (c *CoinbaseStore) NewRecord(height uint64, amount int64) (CoinbaseRecord, error) {
	var blind [32]byte
	if _, err := rand.Read(blind[:]); err != nil {
		return CoinbaseRecord{}, err
	}
	commit, err := v2crypto.PedersenCommit(amount, blind[:])
	if err != nil {
		return CoinbaseRecord{}, err
	}
	return CoinbaseRecord{Height: height, Amount: amount, Blinding: blind, Commit: commit}, nil
}

// Persist durably stores rec (fsync of file and directory). It is idempotent
// for a commitment already stored. A full file is archived first.
func (c *CoinbaseStore) Persist(rec CoinbaseRecord) error {
	want, err := v2crypto.PedersenCommit(rec.Amount, rec.Blinding[:])
	if err != nil || want != rec.Commit {
		return errors.New("coinbase: record does not open its commitment")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.all {
		if c.all[i].Commit == rec.Commit {
			return nil
		}
	}
	if c.dirSyncPending {
		if err := syncDirFn(c.path); err != nil {
			return fmt.Errorf("coinbase: syncing the key directory: %w", err)
		}
		c.dirSyncPending = false
	}
	if len(c.all) >= CoinbaseRotateRecords {
		if err := c.rotateLocked(); err != nil {
			return err
		}
	}
	c.all = append(c.all, rec)
	if err := c.flushLocked(); err != nil {
		c.all = c.all[:len(c.all)-1]
		return err
	}
	return nil
}

// rotateLocked archives the current file under a unique name and empties the
// in-memory set. The archive stays a valid, importable coinbases file.
func (c *CoinbaseStore) rotateLocked() error {
	if c.path == "" {
		return errors.New("coinbase: no store path")
	}
	if len(c.all) == 0 {
		return nil
	}
	var archive string
	for i := 0; ; i++ {
		archive = fmt.Sprintf("%s.%d.%d", c.path, time.Now().UnixNano(), i)
		if _, err := os.Lstat(archive); os.IsNotExist(err) {
			break
		} else if err != nil {
			return err
		}
	}
	// replaceFile is the platform's durable rename (MOVEFILE_WRITE_THROUGH on
	// Windows, where a directory cannot be fsynced); archive does not exist.
	if err := replaceFile(c.path, archive); err != nil {
		return err
	}
	// From here the keys are in the archive and the in-memory set is empty: a
	// failure below must not leave c.all full while the live file is gone (every
	// later Persist would fail at the rename and the miner would withhold blocks
	// until restart).
	c.all = nil
	c.dirSyncPending = true
	// The rename must be durable before the live file is rewritten, or a crash
	// could keep the new (small) file and lose the archive's keys. A failure
	// here makes Persist fail, so the solved block is withheld; the next Persist
	// retries the sync.
	if err := syncDirFn(archive); err != nil {
		return fmt.Errorf("coinbase: syncing the key directory: %w", err)
	}
	c.dirSyncPending = false
	return nil
}

// Allocate is NewRecord followed by Persist.
func (c *CoinbaseStore) Allocate(height uint64, amount int64) (CoinbaseRecord, error) {
	rec, err := c.NewRecord(height, amount)
	if err != nil {
		return CoinbaseRecord{}, err
	}
	if err := c.Persist(rec); err != nil {
		return CoinbaseRecord{}, err
	}
	return rec, nil
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
	if len(c.all) > MaxCoinbaseRecords {
		return errors.New("coinbase: record bound exceeded")
	}
	body, err := json.MarshalIndent(c.all, "", "  ")
	if err != nil {
		return err
	}
	return atomicSecretWrite(c.path, body)
}

// coinbaseDomain tags the coinbase kernel digest (NUL terminated, like every
// NosoX/<name>/v5 domain) so a signature made for it cannot be replayed as any
// other Schnorr message.
const coinbaseDomain = "NosoX/coinbase-kernel/v5\x00"

// CoinbaseKernelSignHash is the canonical digest the miner signs for a
// coinbase kernel:
//
//	SHA-256("NosoX/coinbase-kernel/v5\0" || BE32(magic) || BE64(height) || BE64(amount) || commit[33])
//
// magic is the network magic of the block header and height its height, so a
// coinbase signature is valid on exactly one network at one height. A verifier
// recomputes it from the block header and the kernel alone.
func CoinbaseKernelSignHash(magic uint32, height uint64, amount int64, commit [33]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(coinbaseDomain))
	var m [4]byte
	binary.BigEndian.PutUint32(m[:], magic)
	h.Write(m[:])
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

// SignCoinbase signs the coinbase kernel for magic/height/amount using the
// blinding factor as the secret scalar. Returns the Schnorr signature
// (65 bytes) ready to embed in Kernel.ExcessSig.
//
// The coinbase kernel's Excess is the output commitment itself, r·G + amount·H;
// the verifier subtracts amount·H (amount = reward + fees, computed by the
// verifier from the block) and checks the signature under the remaining r·G.
// Knowing r is therefore knowing the kernel's secret key, and the signature
// proves the commitment holds exactly that amount.
func SignCoinbase(magic uint32, rec CoinbaseRecord) ([]byte, error) {
	msg := CoinbaseKernelSignHash(magic, rec.Height, rec.Amount, rec.Commit)
	return v2cryptoSchnorrSign(rec.Blinding[:], msg[:])
}

// VerifyCoinbase checks the Schnorr signature on a coinbase kernel.
// Standalone helper so the chain validator can call it without pulling
// in the wallet package.
func VerifyCoinbase(magic uint32, height uint64, amount int64, commit [33]byte, sig []byte) bool {
	msg := CoinbaseKernelSignHash(magic, height, amount, commit)
	// The excess "public key" equals the commitment IFF amount == 0.
	// For a coinbase the kernel-excess commit is r·G + amount·H. We
	// verify Schnorr against (commit - amount·H), but since amount and
	// commit are known by every validator, this is straightforward to
	// recompute. The helper below does it.
	return v2cryptoVerifyCoinbase(commit, amount, msg[:], sig)
}
