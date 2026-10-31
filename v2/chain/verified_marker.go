package chain

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dgraph-io/badger/v4"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pasichDev/noso-go/v2/types"
)

// Verified-history marker.
//
// Replaying every block (Argon2, signatures, range proofs) at each start costs
// hours on a Raspberry Pi for a year of history. After a node has validated
// history it records (genesis, height, tip hash) in <datadir>/verified.json.
// On the next start the node:
//
//  1. checks the marker file's own checksum, schema, network and genesis;
//  2. checks that the stored chain still contains the marker's tip at its height;
//  3. walks every stored block checking parent links and body roots (no proofs);
//  4. fully re-validates only the blocks after the marker (they were accepted
//     after the marker was last written, e.g. before a crash).
//
// Any failure falls back to the complete replay, which is also forced by
// SetFullVerify (nosoxd -verify-full). The marker protects against crashes,
// partial writes and storage corruption; it is not a MAC, so someone who can
// rewrite the database and the marker can also bypass it, as such a person
// could bypass a replay by replacing the binary. Run with -verify-full after
// restoring a datadir from an untrusted source.

const (
	markerFile   = "verified.json"
	markerSchema = 2
	// consensusRulesVersion identifies the block-validation rules the marker was
	// written under. Bump it with any consensus change: older markers then force
	// one complete replay. 2: dev fund removed, coinbase pays reward + fees.
	consensusRulesVersion = 2
	markerInterval        = 256 // blocks between marker refreshes while running
	replayPrefix          = ".nosox-replay-"
)

type verifiedMarker struct {
	Schema int `json:"schema"`
	// Rules and Checkpoints bind the marker to the consensus rules and the
	// checkpoint set it was verified under; a mismatch forces a full replay.
	Rules       int    `json:"rules"`
	Checkpoints string `json:"checkpoints"`
	Magic       uint32 `json:"magic"`
	Genesis     string `json:"genesis"`
	Height      uint64 `json:"height"`
	Tip         string `json:"tip"`
	Check       string `json:"check"`
}

// checkpointSetHash is a digest of the installed checkpoint set (order
// independent), or the empty string for no checkpoints.
func checkpointSetHash(cps []types.Checkpoint) string {
	if len(cps) == 0 {
		return ""
	}
	sorted := append([]types.Checkpoint(nil), cps...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Height < sorted[j].Height })
	h := sha256.New()
	h.Write([]byte("NosoX/checkpoints/v1"))
	for _, cp := range sorted {
		var hb [8]byte
		binary.BigEndian.PutUint64(hb[:], cp.Height)
		h.Write(hb[:])
		h.Write(cp.Hash[:])
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (m verifiedMarker) checksum() string {
	h := sha256.Sum256([]byte(fmt.Sprintf("NosoX/verified/v2|%d|%d|%s|%d|%s|%d|%s", m.Schema, m.Rules, m.Checkpoints, m.Magic, m.Genesis, m.Height, m.Tip)))
	return hex.EncodeToString(h[:])
}

// cleanReplayScratch removes scratch databases a killed replay left beside the
// data directory. Only plain directories with the replay prefix are touched.
func cleanReplayScratch(parent string) {
	entries, err := os.ReadDir(parent)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), replayPrefix) {
			continue
		}
		p := filepath.Join(parent, e.Name())
		if info, err := os.Lstat(p); err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
			_ = os.RemoveAll(p)
		}
	}
}

// openVerifiedBadger verifies a non-empty persistent chain, skipping the full
// replay when a trustworthy marker covers it. Caller holds writeMu and mu.
func (c *Chain) openVerifiedBadger(s *BadgerStore, dir string, genesis *types.Block) error {
	cleanReplayScratch(filepath.Dir(s.db.Opts().Dir))
	if !c.fullVerify {
		if ok, err := c.verifyFromMarker(s, dir, genesis); err != nil {
			return err
		} else if ok {
			c.markerDir = dir
			// The marker is an optimisation: failing to write it must not throw
			// away a verification that just passed (it only costs a replay later).
			_ = c.writeMarkerLocked()
			return nil
		}
	}
	if err := c.verifyHistory(s, genesis); err != nil {
		return err
	}
	c.markerDir = dir
	_ = c.writeMarkerLocked() // a replay of hours must not be discarded for ENOSPC
	return nil
}

func readMarker(dir string) (verifiedMarker, bool) {
	raw, err := os.ReadFile(filepath.Join(dir, markerFile))
	if err != nil || len(raw) > 4096 {
		return verifiedMarker{}, false
	}
	var m verifiedMarker
	if json.Unmarshal(raw, &m) != nil || m.Schema != markerSchema || m.Check != m.checksum() {
		return verifiedMarker{}, false
	}
	return m, true
}

// verifyFromMarker returns (true, nil) when the marker covers the stored chain
// and every check passed; (false, nil) to request a full replay; an error only
// when the blocks after the marker are invalid.
func (c *Chain) verifyFromMarker(s *BadgerStore, dir string, genesis *types.Block) (bool, error) {
	m, ok := readMarker(dir)
	if !ok {
		return false, nil
	}
	gid := types.HeaderID(&genesis.Header)
	if m.Magic != genesis.Header.NetworkMagic || m.Genesis != hex.EncodeToString(gid[:]) {
		return false, nil
	}
	if m.Rules != consensusRulesVersion || m.Checkpoints != checkpointSetHash(c.checkpoints) {
		return false, nil // other rules or checkpoints: only a full replay can vouch
	}
	tip, ok := s.Tip()
	if !ok || tip.Height < m.Height || tip.Height-m.Height > MaxReorgBlocks {
		return false, nil
	}
	want, err := hex.DecodeString(m.Tip)
	if err != nil || len(want) != len(types.Hash{}) {
		return false, nil
	}
	var wantID types.Hash
	copy(wantID[:], want)
	if h, ok := s.HeightOf(wantID); !ok || h != m.Height {
		return false, nil
	}
	total, err := c.structuralPass(s, gid)
	if err != nil {
		return false, nil
	}
	if tip.Height == m.Height {
		c.seedWorkLocked(total)
		return true, nil
	}
	// Blocks after the marker: roll the store view back to the marker height
	// and apply them again under the full rules (without the wall-clock rule).
	staged, err := newForkStore(s, m.Height)
	if err != nil {
		return false, nil
	}
	check := &Chain{store: staged, checkpoints: c.checkpoints, now: c.now}
	for h := m.Height + 1; h <= tip.Height; h++ {
		b, err := s.BlockAt(h)
		if err != nil {
			return false, nil
		}
		if err := check.validate(b, false); err != nil {
			return false, fmt.Errorf("chain: invalid persisted block %d: %w", h, err)
		}
		if err := staged.WriteBlock(b); err != nil {
			return false, nil
		}
	}
	c.seedWorkLocked(total)
	return true, nil
}

// seedWorkLocked installs the accumulated work of the current tip, computed
// while loading, so the first TotalWork call does not walk the chain under mu.
func (c *Chain) seedWorkLocked(total *big.Int) {
	tip, ok := c.store.Tip()
	if !ok {
		return
	}
	c.work = workCache{total: total, tip: types.HeaderID(&tip), height: tip.Height}
}

// structuralPass walks the stored chain once, checking genesis identity, parent
// links, heights and body roots. It performs no proof-of-work or proof work.
func (c *Chain) structuralPass(s *BadgerStore, genesisID types.Hash) (*big.Int, error) {
	snapshot, release := s.snapshot()
	defer release()
	var prev types.Hash
	total := new(big.Int)
	expect := newStateDigest()
	tipItem, err := snapshot.Get([]byte{kTip})
	if err != nil {
		return nil, err
	}
	var tipHeight uint64
	if err := tipItem.Value(func(raw []byte) error {
		if len(raw) != 8 {
			return errors.New("chain: invalid persisted tip")
		}
		tipHeight = bytesToU64(raw)
		return nil
	}); err != nil {
		return nil, err
	}
	for h := uint64(0); h <= tipHeight; h++ {
		b, err := replayBlockAt(snapshot, h)
		if err != nil {
			return nil, err
		}
		total.Add(total, blockWork(b.Header.Difficulty))
		id := types.HeaderID(&b.Header)
		if h == 0 {
			if id != genesisID {
				return nil, errors.New("chain: stored genesis differs from trusted genesis")
			}
		} else if b.Header.PrevHash != prev || b.Header.Height != h {
			return nil, fmt.Errorf("chain: broken link at %d", h)
		}
		if h > 0 {
			if err := validateStructure(b); err != nil {
				return nil, fmt.Errorf("chain: block %d: %w", h, err)
			}
		}
		if cp, ok := types.CheckpointForHeight(c.checkpoints, h); ok && id != cp.Hash {
			return nil, fmt.Errorf("chain: stored block %d conflicts with the checkpoint: %w", h, ErrCheckpoint)
		}
		expect.addBlock(b)
		prev = id
		if h == tipHeight {
			break
		}
	}
	// The derived indexes (unspent outputs, output and kernel history) must be
	// exactly what the stored blocks imply. Keys only: no values are decoded.
	actual, err := scanStateDigest(snapshot)
	if err != nil {
		return nil, err
	}
	if !expect.equal(actual) {
		return nil, errors.New("chain: persisted UTXO/output/kernel indexes differ from the stored blocks")
	}
	return total, nil
}

// stateDigest summarises the three derived key sets (unspent outputs, every
// output ever created, every kernel ever included) as a count and an additive
// hash of the keys, so two sets are equal exactly when both match. It is
// order independent, which lets blocks be folded in one at a time.
type stateDigest struct {
	count [3]int64
	sum   [3]*big.Int
}

var digestMod = new(big.Int).Lsh(big.NewInt(1), 256)

const (
	dgUTXO = iota
	dgOutput
	dgKernel
)

func newStateDigest() *stateDigest {
	return &stateDigest{sum: [3]*big.Int{new(big.Int), new(big.Int), new(big.Int)}}
}

func (d *stateDigest) add(set int, prefix byte, id []byte, sign int) {
	h := sha256.Sum256(append([]byte{prefix}, id...))
	v := new(big.Int).SetBytes(h[:])
	if sign < 0 {
		v.Neg(v)
	}
	d.sum[set].Add(d.sum[set], v).Mod(d.sum[set], digestMod)
	d.count[set] += int64(sign)
}

// addBlock folds one canonical block: outputs create UTXO and history entries,
// inputs retire UTXO entries, kernels enter the kernel history.
func (d *stateDigest) addBlock(b *types.Block) {
	for i := range b.Outputs {
		c := b.Outputs[i].Commit
		d.add(dgUTXO, kUTXO, c[:], 1)
		d.add(dgOutput, kOutputSeen, c[:], 1)
	}
	for i := range b.Inputs {
		c := b.Inputs[i].Commit
		d.add(dgUTXO, kUTXO, c[:], -1)
	}
	for i := range b.Kernels {
		id := types.KernelID(&b.Kernels[i])
		d.add(dgKernel, kKernelSeen, id[:], 1)
	}
}

func (d *stateDigest) equal(o *stateDigest) bool {
	for i := range d.count {
		if d.count[i] != o.count[i] || d.sum[i].Cmp(o.sum[i]) != 0 {
			return false
		}
	}
	return true
}

// scanStateDigest digests the stored u/o/k key sets with a keys-only scan.
func scanStateDigest(txn *badger.Txn) (*stateDigest, error) {
	d := newStateDigest()
	for _, p := range []struct {
		set    int
		prefix byte
	}{{dgUTXO, kUTXO}, {dgOutput, kOutputSeen}, {dgKernel, kKernelSeen}} {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		opts.Prefix = []byte{p.prefix}
		it := txn.NewIterator(opts)
		for it.Rewind(); it.Valid(); it.Next() {
			key := it.Item().Key()
			d.add(p.set, p.prefix, key[1:], 1)
		}
		it.Close()
	}
	return d, nil
}

// writeMarkerLocked records the current tip as verified. Caller holds mu.
func (c *Chain) writeMarkerLocked() error {
	if c.markerDir == "" {
		return nil
	}
	tip, ok := c.store.Tip()
	if !ok {
		return nil
	}
	g, err := c.store.BlockAt(0)
	if err != nil {
		return err
	}
	gid, tid := types.HeaderID(&g.Header), types.HeaderID(&tip)
	m := verifiedMarker{Schema: markerSchema, Rules: consensusRulesVersion, Checkpoints: checkpointSetHash(c.checkpoints), Magic: g.Header.NetworkMagic, Genesis: hex.EncodeToString(gid[:]), Height: tip.Height, Tip: hex.EncodeToString(tid[:])}
	m.Check = m.checksum()
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	path := filepath.Join(c.markerDir, markerFile)
	tmp, err := os.CreateTemp(c.markerDir, ".verified-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	c.sinceMarker = 0
	return nil
}

// noteAppendedLocked is called after n blocks were committed; it refreshes the
// marker every markerInterval blocks so a crash leaves a short unverified tail.
func (c *Chain) noteAppendedLocked(n uint64) {
	if c.markerDir == "" {
		return
	}
	c.sinceMarker += n
	if c.sinceMarker >= markerInterval {
		_ = c.writeMarkerLocked()
	}
}
