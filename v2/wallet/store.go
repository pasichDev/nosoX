package wallet

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"sort"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/pasichDev/noso-go/v2/types"
)

// Wallet state lives in "<wallet>.outputs": ONE encrypted file holding every
// tracked output, every live nonce context and every signed-but-unconfirmed
// transaction. It is deliberately a single file so that the transitions that
// must be atomic together ("lock inputs + persist nonce", "erase nonce + store
// final transaction + mark inputs spent") are a single rename.
//
// Encryption is the keystore scheme (version 2 envelope: Argon2id with the
// parameters stored in the file -> XChaCha20-Poly1305, fresh random 24-byte
// nonce per write) with its own random salt and a distinct AEAD additional-data
// label that also covers version, salt and parameters, so the two files cannot
// be swapped and the parameters cannot be altered. The Argon2 key is derived
// once when the store is opened, not per write.

// OutputStatus is the lifecycle state of a tracked output.
type OutputStatus string

const (
	// StatusPending: not yet seen on chain (fresh change, received output, or an
	// imported coinbase the node has not confirmed).
	StatusPending OutputStatus = "pending"
	// StatusUnspent: confirmed on chain and free to select.
	StatusUnspent OutputStatus = "unspent"
	// StatusLocked: reserved as an input of an in-flight (not yet signed) payment.
	StatusLocked OutputStatus = "locked"
	// StatusSpent: committed to a signed transaction, or seen spent on chain.
	StatusSpent OutputStatus = "spent"
)

// Output origins.
const (
	OriginCoinbase = "coinbase"
	OriginChange   = "change"
	OriginReceive  = "receive"
)

const (
	stateVersion = 2
	// maxOutputRecords bounds how many NOT-yet-final records (pending, unspent,
	// locked) an import or a receive may add. maxLoadRecords is the hard bound on
	// all live records, shared by write and load ("load never refuses what write
	// accepted"); the room between the two is what a payment's change and the
	// spent inputs of recent payments need, so a payment never needs the soft
	// bound. Both are chosen together with maxStatePlain (see
	// TestWorstCaseStateFitsTheByteBound): the byte bound, not the count, is what
	// limits the file.
	maxOutputRecords = 10000
	maxLoadRecords   = 16384
	maxContexts      = 32
	maxSentTxs       = 32
	// pendingReceiveTTL is how long an unconfirmed incoming output stays a live
	// record before sync moves it to the archive (only when the node does not
	// have it). It is never deleted: the sender may still hold the finished
	// transaction and mine it later.
	pendingReceiveTTL = 30 * 24 * time.Hour
	// maxArchived bounds the archived unconfirmed RECEIVES. It is a hard bound
	// shared by write and load; Receive refuses new offers when it is reached (it
	// never evicts). Retired keys (spent, stale candidate, abandoned change) live
	// in the same list but are bounded by maxRetired, so they can never fill the
	// receive quota.
	maxArchived = 2048
	// maxRetired bounds archived keys that once could hold value: spent outputs
	// buried pruneDepth blocks, coinbase candidates that never landed, change of
	// abandoned payments. A key is evicted only when this section is full and the
	// entry is older than retiredRetention by the LOCAL clock; a node's answer
	// never evicts anything.
	maxRetired       = maxLoadRecords
	retiredRetention = 180 * 24 * time.Hour
	// maxStatePlain bounds the plaintext state; maxStateFileBytes the file
	// (base64 inflates by 4/3).
	maxStatePlain     = 20 << 20
	maxStateFileBytes = 32 << 20
	// pruneDepth is the number of blocks after which a spend, or a never-landed
	// coinbase candidate, is considered final and its live record is MOVED to the
	// encrypted archive (never deleted). It must
	// not be smaller than types.MaxReorgBlocks: a reorg replaces at most that
	// many blocks, so a block pruneDepth below the tip can no longer change.
	pruneDepth = 1024
	// DefaultMinConfirmations is the depth at which an output counts as confirmed.
	DefaultMinConfirmations = 10
	// maxMinConfirmations bounds the configurable depth.
	maxMinConfirmations = 10000
	// StateSuffix is appended to the wallet path.
	StateSuffix = ".outputs"
)

// OutputRecord is one tracked output.
type OutputRecord struct {
	Commit     string       `json:"commit"` // hex, 33 bytes
	Value      int64        `json:"value"`
	Blinding   []byte       `json:"blinding"` // 32 bytes, SECRET
	Features   uint8        `json:"features"`
	Status     OutputStatus `json:"status"`
	Origin     string       `json:"origin"`
	Height     uint64       `json:"height,omitempty"`      // claimed (coinbase) or observed creation height
	MaturesAt  uint64       `json:"matures_at,omitempty"`  // first block height that may spend it (coinbase only)
	TxID       string       `json:"txid,omitempty"`        // tx that created it (change/receive)
	LockedBy   string       `json:"locked_by,omitempty"`   // tx that reserved/spent it
	BlockHash  string       `json:"block_hash,omitempty"`  // block that created it, as last seen on chain
	ChainSpent bool         `json:"chain_spent,omitempty"` // seen spent on chain (confirmed spend)
	SpentTip   uint64       `json:"spent_tip,omitempty"`   // node tip when the spend was first seen (prune horizon)
	Created    int64        `json:"created,omitempty"`     // unix time the record was added (pending receive TTL)
}

// TxContext is the sender's per-payment secret state: it exists from the moment
// a slate is offered until the final signature is computed, and never after.
type TxContext struct {
	TxID    string `json:"txid"`
	Offer   []byte `json:"offer"` // binary offer slate, exactly what was emitted
	XS      []byte `json:"xs"`    // sender excess scalar, SECRET
	KS      []byte `json:"ks"`    // sender nonce scalar, SECRET
	Created int64  `json:"created"`
}

// SentTx is a fully signed transaction. It holds no secrets. A retry of
// finalize resubmits Tx byte for byte and never signs again.
type SentTx struct {
	TxID      string   `json:"txid"`
	Tx        []byte   `json:"tx"`
	Resp      string   `json:"resp"`   // sha256 of the receiver response slate this was built from
	Inputs    []string `json:"inputs"` // hex commits
	Submitted bool     `json:"submitted"`
	Created   int64    `json:"created"`
}

// ArchivedReceive is a compact record of an unconfirmed incoming output that
// outlived pendingReceiveTTL. It still holds the blinding factor (SECRET, and
// encrypted with the rest of the state): the sender may finalize and mine the
// transaction long after the live record expired, and without the blinding
// factor those funds could never be spent. Sync keeps asking the node about
// archived commitments and restores the full record when one appears on chain.
type ArchivedReceive struct {
	Commit   string `json:"commit"` // hex, 33 bytes
	Value    int64  `json:"value"`
	Blinding []byte `json:"blinding"` // 32 bytes, SECRET
	TxID     string `json:"txid,omitempty"`
	Created  int64  `json:"created,omitempty"` // unix time the receive was first recorded
	// Retired keys (Reason != "") keep what is needed to bring them back:
	Origin   string `json:"origin,omitempty"`
	Features uint8  `json:"features,omitempty"`
	Height   uint64 `json:"height,omitempty"`
	Reason   string `json:"reason,omitempty"`   // "" = unconfirmed receive; see archReason*
	Archived int64  `json:"archived,omitempty"` // unix time the entry was archived (local clock)
}

type walletState struct {
	Version int            `json:"version"`
	Master  []byte         `json:"master"` // Ed25519 public key of the owning wallet
	Outputs []OutputRecord `json:"outputs"`
	// Archive holds expired unconfirmed receives (see ArchivedReceive). It is
	// not counted against maxOutputRecords or maxPendingReceives.
	Archive  []ArchivedReceive `json:"archive,omitempty"`
	Contexts []TxContext       `json:"contexts"`
	Sent     []SentTx          `json:"sent"`
	Tip      uint64            `json:"tip"` // lowest node tip height seen at the last sync
	Synced   bool              `json:"synced"`
	// SyncedAt is the local unix time of the last sync; it bounds how far a node's
	// tip may move since (see checkTip).
	SyncedAt int64 `json:"synced_at,omitempty"`
	// ArchiveCursor rotates the archive entries asked about per sync.
	ArchiveCursor int `json:"archive_cursor,omitempty"`
	// Gen counts state writes. A sidecar file (see checkGeneration) remembers
	// the highest value written, so a state older than the sidecar is a restored
	// backup.
	Gen uint64 `json:"gen"`
	// Magic pins the wallet to one network (0 = not yet pinned).
	Magic uint32 `json:"magic,omitempty"`
	// Suspect lists live contexts that existed when a rollback was detected;
	// they must be cancelled, never finalized (a restored nonce could be reused).
	Suspect []string `json:"suspect,omitempty"`
}

// Store is the open, locked, decrypted wallet state.
type Store struct {
	mu   sync.Mutex
	path string
	key  []byte
	salt []byte
	kdf  KDFParams
	lock *os.File
	st   walletState
	now  func() time.Time

	// minConf is the depth at which an output counts as confirmed.
	minConf uint64

	// writeHook, when set, runs before every state write and can fail it
	// (crash-consistency tests).
	writeHook func() error

	// broken is set when memory could not be re-synchronized with the file after
	// a failed write; writes are refused until a reload succeeds.
	broken error
}

// StatePath returns the state file path for a wallet path.
func StatePath(walletPath string) string { return walletPath + StateSuffix }

// OpenStore takes the process lock, derives the encryption key and loads (or
// initializes in memory) the state belonging to master. A missing file is an
// empty state; it is created on the first mutation. A version 1 state file is
// migrated to version 2 (stronger KDF, authenticated parameters) on open.
func OpenStore(walletPath, passphrase string, master ed25519.PublicKey) (*Store, error) {
	if passphrase == "" || len(master) != ed25519.PublicKeySize {
		return nil, errors.New("wallet: store requires a passphrase and master public key")
	}
	path := StatePath(walletPath)
	lk, err := lockFile(path + ".lock")
	if err != nil {
		return nil, err
	}
	s := &Store{path: path, lock: lk, now: time.Now, minConf: uint64(defaultMinConfirmations)}
	s.st = walletState{Version: stateVersion, Master: append([]byte(nil), master...)}
	migrate := false
	body, rerr := readBounded(path, maxStateFileBytes)
	switch {
	case rerr == nil:
		var enc Encrypted
		if err := json.Unmarshal(body, &enc); err != nil {
			unlockFile(lk)
			return nil, fmt.Errorf("wallet: parse %s: %w", path, err)
		}
		salt, err := base64.StdEncoding.Strict().DecodeString(enc.Salt)
		if err != nil || len(salt) != 16 {
			unlockFile(lk)
			return nil, errors.New("wallet: invalid state envelope")
		}
		var kdf KDFParams
		var aad []byte
		switch enc.Version {
		case envelopeV1:
			kdf, aad, migrate = legacyKDF, []byte(legacyStateAAD), true
		case envelopeV2:
			if enc.KDF == nil {
				unlockFile(lk)
				return nil, errors.New("wallet: invalid state envelope")
			}
			kdf = *enc.KDF
			if err := kdf.validate(); err != nil {
				unlockFile(lk)
				return nil, err
			}
			aad = envelopeAAD(labelState, envelopeV2, salt, kdf)
		default:
			unlockFile(lk)
			return nil, errors.New("wallet: invalid state envelope")
		}
		s.salt, s.kdf = salt, kdf
		s.key = deriveKey(passphrase, salt, kdf)
		_ = LockBytes(s.key)
		if err := s.loadEnvelope(&enc, aad); err != nil {
			s.Close()
			return nil, err
		}
		if migrate {
			// Re-key under the current parameters and a fresh salt; the first
			// write below replaces the version 1 file.
			Zeroize(s.key)
			UnlockBytes(s.key)
			s.salt = make([]byte, 16)
			if _, err := rand.Read(s.salt); err != nil {
				s.Close()
				return nil, err
			}
			s.kdf = kdfDefault
			s.key = deriveKey(passphrase, s.salt, s.kdf)
			_ = LockBytes(s.key)
		}
	case os.IsNotExist(rerr):
		if _, gerr := os.Lstat(path + ".gen"); gerr == nil {
			// The generation marker is written after every state write: a marker
			// without its state means the state was deleted or not restored, and
			// silently starting empty would hide every tracked output and nonce.
			unlockFile(lk)
			return nil, fmt.Errorf("wallet: %s is missing but its generation marker %s.gen exists; restore the state file from a backup (remove the marker only to deliberately start over, which forgets every tracked output)", path, path)
		}
		s.salt = make([]byte, 16)
		if _, err := rand.Read(s.salt); err != nil {
			unlockFile(lk)
			return nil, err
		}
		s.kdf = kdfDefault
		s.key = deriveKey(passphrase, s.salt, s.kdf)
		_ = LockBytes(s.key)
	default:
		unlockFile(lk)
		return nil, rerr
	}
	if subtle.ConstantTimeCompare(s.st.Master, master) != 1 {
		s.Close()
		return nil, errors.New("wallet: state file belongs to a different wallet")
	}
	dirty := s.checkGeneration() || migrate
	if s.sanitizeTip() {
		dirty = true
	}
	// Recover an over-full state written by an older build: drop what is final.
	if s.pruneLocked(s.st.Tip) {
		dirty = true
	}
	if dirty {
		if err := s.commit(); err != nil && !errors.Is(err, ErrWrittenUnconfirmed) {
			s.Close()
			return nil, fmt.Errorf("wallet: could not rewrite the state on open: %w", err)
		}
	}
	return s, nil
}

// SetMinConfirmations sets the depth at which an output counts as confirmed
// (and may be spent). Valid range 1..10000; the default is 10.
func (s *Store) SetMinConfirmations(n int) error {
	if n < 1 || n > maxMinConfirmations {
		return fmt.Errorf("wallet: confirmations must be between 1 and %d", maxMinConfirmations)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.minConf = uint64(n)
	return nil
}

// defaultMinConfirmations is a variable only so tests can use a shallow depth.
var defaultMinConfirmations = DefaultMinConfirmations

// deep reports whether info is buried at least minConf blocks (the creating
// block counts as the first).
func (s *Store) deep(info UTXOInfo) bool {
	// minConf >= 1: the creating block counts as the first confirmation.
	return info.Tip >= info.Height && info.Tip-info.Height >= s.minConf-1
}

// reachesDepth reports tip >= base+depth without overflowing.
func reachesDepth(tip, base, depth uint64) bool { return tip >= base && tip-base >= depth }

// addSat is a+b saturating at the maximum.
func addSat(a, b uint64) uint64 {
	if a > math.MaxUint64-b {
		return math.MaxUint64
	}
	return a + b
}

// ---- anti-rollback -----------------------------------------------------

func (s *Store) genPath() string { return s.path + ".gen" }

type genFile struct {
	Gen uint64 `json:"gen"`
	MAC string `json:"mac"` // hex HMAC(state key, gen)
}

// readGen returns the sidecar generation, ok=false when it is missing or fails
// authentication.
func (s *Store) readGen() (uint64, bool) {
	body, err := readBoundedSecret(s.genPath())
	if err != nil {
		return 0, false
	}
	var g genFile
	if json.Unmarshal(body, &g) != nil {
		return 0, false
	}
	mac, err := hex.DecodeString(g.MAC)
	if err != nil || !hmac.Equal(mac, macGen(s.key, g.Gen)) {
		return 0, false
	}
	return g.Gen, true
}

func (s *Store) writeGen() error {
	body, err := json.Marshal(genFile{Gen: s.st.Gen, MAC: hex.EncodeToString(macGen(s.key, s.st.Gen))})
	if err != nil {
		return err
	}
	return atomicSecretWrite(s.genPath(), body)
}

// checkGeneration compares the loaded state with the sidecar written after every
// state write. A state older than the sidecar (or a state that has been written
// before but has no valid sidecar) cannot be shown to be current: every live
// nonce context is marked suspect and Finalize refuses it. This defeats
// "restore an old backup, then sign a second, different transaction with the
// nonce the backup still holds" unless the attacker also restores or forges
// the sidecar, which needs the same file access as the backup restore itself
// (see docs/wallet.md). It reports whether the state needs a rewrite.
func (s *Store) checkGeneration() bool {
	g, ok := s.readGen()
	switch {
	case ok && g <= s.st.Gen:
		return false
	case !ok && s.st.Gen == 0:
		return false // brand new or pre-sidecar state: the first write creates it
	}
	for _, c := range s.st.Contexts {
		s.st.Suspect = appendUnique(s.st.Suspect, c.TxID)
	}
	if ok && g > s.st.Gen {
		s.st.Gen = g // never go backwards again
	}
	return true
}

// Suspect reports whether the live payment txid was present when a rollback of
// this state was detected.
func (s *Store) isSuspect(txid string) bool {
	for _, x := range s.st.Suspect {
		if x == txid {
			return true
		}
	}
	return false
}

func (s *Store) loadEnvelope(enc *Encrypted, aad []byte) error {
	nonce, err := base64.StdEncoding.Strict().DecodeString(enc.Nonce)
	if err != nil || len(nonce) != chacha20poly1305.NonceSizeX {
		return errors.New("wallet: invalid state nonce")
	}
	ct, err := base64.StdEncoding.Strict().DecodeString(enc.Ciphertext)
	if err != nil || len(ct) < chacha20poly1305.Overhead {
		return errors.New("wallet: invalid state ciphertext")
	}
	aead, err := chacha20poly1305.NewX(s.key)
	if err != nil {
		return err
	}
	plain, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return fmt.Errorf("wallet: decrypt state: %w (bad passphrase or corrupt file)", err)
	}
	defer Zeroize(plain)
	var st walletState
	dec := json.NewDecoder(bytes.NewReader(plain))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&st); err != nil {
		return fmt.Errorf("wallet: state: %w", err)
	}
	if (st.Version != 1 && st.Version != stateVersion) || len(st.Outputs) > maxLoadRecords || len(st.Archive) > maxArchived+maxRetired || len(st.Contexts) > maxContexts || len(st.Sent) > maxSentTxs {
		return errors.New("wallet: state version or bounds")
	}
	st.Version = stateVersion
	seen := map[string]bool{}
	for i := range st.Outputs {
		o := &st.Outputs[i]
		c, err := hex.DecodeString(o.Commit)
		if err != nil || len(c) != 33 || len(o.Blinding) != 32 || o.Value <= 0 || seen[o.Commit] {
			return errors.New("wallet: corrupt output record")
		}
		switch o.Status {
		case StatusPending, StatusUnspent, StatusLocked, StatusSpent:
		default:
			return errors.New("wallet: corrupt output status")
		}
		seen[o.Commit] = true
	}
	for i := range st.Archive {
		a := &st.Archive[i]
		c, err := hex.DecodeString(a.Commit)
		if err != nil || len(c) != 33 || len(a.Blinding) != 32 || a.Value <= 0 || seen[a.Commit] {
			return errors.New("wallet: corrupt archived record")
		}
		switch a.Reason {
		case "", archReasonSpent, archReasonCandidate, archReasonChange:
		default:
			return errors.New("wallet: corrupt archived record")
		}
		seen[a.Commit] = true
	}
	s.wipeState()
	s.st = st
	return nil
}

// reload discards unsaved in-memory changes after a failed write. If memory
// cannot be brought back in line with the file the store is marked broken and
// refuses to write until a reload succeeds, instead of carrying on silently.
func (s *Store) reload() {
	body, err := readBounded(s.path, maxStateFileBytes)
	if err != nil {
		if os.IsNotExist(err) {
			master := s.st.Master
			s.wipeState()
			s.st = walletState{Version: stateVersion, Master: master}
			s.broken = nil
			return
		}
		s.broken = fmt.Errorf("reloading the state: %w", err)
		return
	}
	var enc Encrypted
	if err := json.Unmarshal(body, &enc); err != nil || enc.Version != envelopeV2 || enc.KDF == nil {
		s.broken = errors.New("reloading the state: unrecognized file")
		return
	}
	salt, err := base64.StdEncoding.Strict().DecodeString(enc.Salt)
	if err != nil || !bytes.Equal(salt, s.salt) || *enc.KDF != s.kdf {
		s.broken = errors.New("reloading the state: the file was replaced by another process")
		return
	}
	if err := s.loadEnvelope(&enc, envelopeAAD(labelState, envelopeV2, s.salt, s.kdf)); err != nil {
		s.broken = fmt.Errorf("reloading the state: %w", err)
		return
	}
	s.broken = nil
}

func (s *Store) wipeState() {
	for i := range s.st.Outputs {
		Zeroize(s.st.Outputs[i].Blinding)
	}
	for i := range s.st.Archive {
		Zeroize(s.st.Archive[i].Blinding)
	}
	for i := range s.st.Contexts {
		Zeroize(s.st.Contexts[i].XS)
		Zeroize(s.st.Contexts[i].KS)
	}
}

// Close zeroizes secrets and releases the process lock. Idempotent.
func (s *Store) Close() {
	if s == nil {
		return
	}
	s.wipeState()
	s.st.Outputs, s.st.Archive, s.st.Contexts = nil, nil, nil
	if s.key != nil {
		Zeroize(s.key)
		UnlockBytes(s.key)
		s.key = nil
	}
	unlockFile(s.lock)
	s.lock = nil
}

// ErrStateFull is returned before any state change when an operation would add
// records beyond the wallet's bound.
var ErrStateFull = errors.New("wallet: too many tracked outputs; run `wallet sync`, then `wallet consolidate` to merge small outputs")

// nonFinal counts the records that can still change money: everything except
// spent ones. This is what imports and receives are rationed by.
func (s *Store) nonFinal() int {
	n := 0
	for i := range s.st.Outputs {
		if s.st.Outputs[i].Status != StatusSpent {
			n++
		}
	}
	return n
}

// roomFor reports whether n more not-yet-final records may be ADDED by an
// import or a receive. Payments do not use it: see ensureSlot.
func (s *Store) roomFor(n int) error {
	if s.nonFinal()+n > maxOutputRecords {
		return fmt.Errorf("%w (have %d, limit %d)", ErrStateFull, s.nonFinal(), maxOutputRecords)
	}
	return s.ensureSlot()
}

// ensureSlot guarantees one more live record can be written. A payment turns
// its inputs into spent records and adds one change record, so the live count
// can grow while the spendable set shrinks; at the hard bound the oldest spends
// seen on chain are moved to the archive (their keys are kept) to make room. A
// payment is therefore never refused for being "full" unless the hard bound is
// reached by records that are all still in flight.
func (s *Store) ensureSlot() error {
	if len(s.st.Outputs) < maxLoadRecords {
		return nil
	}
	s.pruneLocked(s.st.Tip)
	if len(s.st.Outputs) < maxLoadRecords {
		return nil
	}
	s.retireChainSpent(maxLoadRecords - 1)
	if len(s.st.Outputs) < maxLoadRecords {
		return nil
	}
	return fmt.Errorf("%w (%d live records, hard limit %d, none finished)", ErrStateFull, len(s.st.Outputs), maxLoadRecords)
}

// commit seals and atomically writes the state (temp file + fsync + rename +
// directory sync). On a failure BEFORE the rename the in-memory state is
// reloaded from disk so memory never runs ahead of what is durable. A failure
// after the rename (ErrWrittenUnconfirmed) keeps memory: the file is in place.
func (s *Store) commit() error {
	if s.key == nil {
		return errors.New("wallet: store closed")
	}
	if err := s.write(); err != nil {
		if errors.Is(err, ErrWrittenUnconfirmed) {
			return err
		}
		s.reload()
		return err
	}
	return nil
}

func (s *Store) write() error {
	if s.broken != nil {
		return fmt.Errorf("wallet: memory may differ from the state file (%w); close and reopen the wallet", s.broken)
	}
	if s.writeHook != nil {
		if err := s.writeHook(); err != nil {
			return err
		}
	}
	// The bounds load enforces are enforced here first, before any I/O.
	if len(s.st.Outputs) > maxLoadRecords || len(s.st.Archive) > maxArchived+maxRetired || len(s.st.Contexts) > maxContexts || len(s.st.Sent) > maxSentTxs {
		return errors.New("wallet: state exceeds its bounds; refusing to write a file that could not be reopened")
	}
	sort.SliceStable(s.st.Outputs, func(i, j int) bool { return s.st.Outputs[i].Commit < s.st.Outputs[j].Commit })
	s.st.Gen++
	plain, err := json.Marshal(&s.st)
	if err != nil {
		return err
	}
	defer Zeroize(plain)
	if len(plain) > maxStatePlain {
		return fmt.Errorf("wallet: state too large (%d tracked outputs); run `wallet sync` to prune finished records", len(s.st.Outputs))
	}
	aead, err := chacha20poly1305.NewX(s.key)
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	kdf := s.kdf
	ct := aead.Seal(nil, nonce, plain, envelopeAAD(labelState, envelopeV2, s.salt, kdf))
	enc := Encrypted{
		Version:    envelopeV2,
		KDF:        &kdf,
		Salt:       base64.StdEncoding.EncodeToString(s.salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
	}
	body, err := json.Marshal(&enc)
	if err != nil {
		return err
	}
	werr := atomicSecretWrite(s.path, body)
	if werr != nil && !errors.Is(werr, ErrWrittenUnconfirmed) {
		return werr
	}
	// The state is in place; record its generation. A failure here leaves the
	// rollback check blind for this write, so it is reported, not swallowed.
	if gerr := s.writeGen(); gerr != nil {
		return fmt.Errorf("%w: generation marker: %v", ErrWrittenUnconfirmed, gerr)
	}
	return werr
}

// ---- pruning -----------------------------------------------------------

// pruneLocked moves records that can no longer matter out of the live set and
// reports whether anything changed. tip is the node tip the horizons are
// measured against.
//   - signed transactions that are submitted and whose every input has been
//     spent on chain for pruneDepth blocks are forgotten (they hold no secrets);
//   - spent outputs seen spent on chain for pruneDepth blocks that no stored
//     transaction still refers to are MOVED to the archive, not deleted;
//   - in the caller (Sync) also stale never-landed coinbase candidates, which
//     need a node answer. Expired unconfirmed receives are archived too.
//
// A key is never destroyed because a node said it was spent: "spent" is the
// node's word, so the key stays (encrypted, in the archive) and a later correct
// answer revives it.
func (s *Store) pruneLocked(tip uint64) bool {
	changed, _ := s.pruneCount(tip)
	return changed
}

func (s *Store) pruneCount(tip uint64) (changed bool, moved int) {
	buried := func(o *OutputRecord) bool {
		return o.Status == StatusSpent && o.ChainSpent && o.SpentTip > 0 && reachesDepth(tip, o.SpentTip, pruneDepth)
	}
	keptSent := s.st.Sent[:0]
	for i := range s.st.Sent {
		t := &s.st.Sent[i]
		done := t.Submitted
		for _, h := range t.Inputs {
			if o := s.output(h); o != nil && !buried(o) {
				done = false
			}
		}
		if done {
			changed = true
			continue
		}
		keptSent = append(keptSent, *t)
	}
	s.st.Sent = keptSent
	referenced := map[string]bool{}
	for i := range s.st.Sent {
		for _, h := range s.st.Sent[i].Inputs {
			referenced[h] = true
		}
	}
	kept := s.st.Outputs[:0]
	for _, o := range s.st.Outputs {
		if buried(&o) && !referenced[o.Commit] && s.archiveOutput(&o, archReasonSpent) {
			Zeroize(o.Blinding) // the archive holds its own copy
			changed = true
			moved++
			continue
		}
		kept = append(kept, o)
	}
	for i := len(kept); i < len(s.st.Outputs); i++ {
		s.st.Outputs[i] = OutputRecord{}
	}
	s.st.Outputs = kept
	return changed, moved
}

// retireChainSpent archives spent-on-chain records, oldest spend first, until
// at most target live records remain (or none is left). Used under pressure
// only; the depth rule of pruneLocked does not apply, which is safe because the
// key is kept either way.
func (s *Store) retireChainSpent(target int) {
	var idx []int
	for i := range s.st.Outputs {
		o := &s.st.Outputs[i]
		if o.Status == StatusSpent && o.ChainSpent {
			idx = append(idx, i)
		}
	}
	sort.SliceStable(idx, func(a, b int) bool { return s.st.Outputs[idx[a]].SpentTip < s.st.Outputs[idx[b]].SpentTip })
	referenced := map[string]bool{}
	for i := range s.st.Sent {
		for _, h := range s.st.Sent[i].Inputs {
			referenced[h] = true
		}
	}
	drop := map[int]bool{}
	for _, i := range idx {
		if len(s.st.Outputs)-len(drop) <= target {
			break
		}
		o := &s.st.Outputs[i]
		if referenced[o.Commit] {
			continue // a stored transaction still refers to it
		}
		if s.archiveOutput(o, archReasonSpent) {
			Zeroize(o.Blinding)
			drop[i] = true
		}
	}
	if len(drop) == 0 {
		return
	}
	kept := s.st.Outputs[:0]
	for i, o := range s.st.Outputs {
		if !drop[i] {
			kept = append(kept, o)
		}
	}
	for i := len(kept); i < len(s.st.Outputs); i++ {
		s.st.Outputs[i] = OutputRecord{}
	}
	s.st.Outputs = kept
}

// ---- queries -----------------------------------------------------------

func commitHex(c types.Commitment) string { return hex.EncodeToString(c[:]) }

func parseCommit(h string) (types.Commitment, error) {
	var c types.Commitment
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != len(c) {
		return c, errors.New("wallet: bad commitment hex")
	}
	copy(c[:], b)
	return c, nil
}

// Outputs returns a copy of the tracked outputs without blinding factors.
func (s *Store) Outputs() []OutputRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]OutputRecord, len(s.st.Outputs))
	for i, o := range s.st.Outputs {
		o.Blinding = nil
		out[i] = o
	}
	return out
}

func (s *Store) output(commit string) *OutputRecord {
	for i := range s.st.Outputs {
		if s.st.Outputs[i].Commit == commit {
			return &s.st.Outputs[i]
		}
	}
	return nil
}

func (s *Store) context(txid string) (int, *TxContext) {
	for i := range s.st.Contexts {
		if s.st.Contexts[i].TxID == txid {
			return i, &s.st.Contexts[i]
		}
	}
	return -1, nil
}

func (s *Store) sent(txid string) (int, *SentTx) {
	for i := range s.st.Sent {
		if s.st.Sent[i].TxID == txid {
			return i, &s.st.Sent[i]
		}
	}
	return -1, nil
}

// Balance summarizes the tracked outputs as of the last sync.
type Balance struct {
	Spendable uint64 `json:"spendable"` // unspent and mature at the next block
	Immature  uint64 `json:"immature"`  // unspent coinbase not yet spendable
	Locked    uint64 `json:"locked"`    // reserved by in-flight payments
	Pending   uint64 `json:"pending"`   // not yet confirmed on chain
	Tip       uint64 `json:"tip"`       // node tip at the last sync
	Synced    bool   `json:"synced"`
}

// Balance returns the current summary. Values are as of the last Sync.
func (s *Store) Balance() Balance {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := Balance{Tip: s.st.Tip, Synced: s.st.Synced}
	for _, o := range s.st.Outputs {
		v := uint64(o.Value)
		switch o.Status {
		case StatusUnspent:
			if o.MaturesAt > addSat(s.st.Tip, 1) {
				b.Immature += v
			} else {
				b.Spendable += v
			}
		case StatusLocked:
			b.Locked += v
		case StatusPending:
			b.Pending += v
		}
	}
	return b
}

// Contexts returns the TxIDs with a live nonce context.
func (s *Store) Contexts() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, c := range s.st.Contexts {
		out = append(out, c.TxID)
	}
	return out
}

// Pending signed transactions (for diagnostics and tests).
func (s *Store) SentTxIDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, c := range s.st.Sent {
		out = append(out, c.TxID)
	}
	return out
}

// archived reports whether commit is in the archive.
func (s *Store) archived(commit string) bool {
	for i := range s.st.Archive {
		if s.st.Archive[i].Commit == commit {
			return true
		}
	}
	return false
}

// ArchivedCount is the number of expired receives kept in the archive.
func (s *Store) ArchivedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.st.Archive)
}

func timeFromUnix(u int64) time.Time { return time.Unix(u, 0) }

// maxPendingReceives bounds unconfirmed incoming outputs: a fake offer costs
// its author nothing, so unconfirmed receives are a rationed resource. A
// variable only so tests can lower it.
var maxPendingReceives = 64
