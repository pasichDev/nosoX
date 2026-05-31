// Package types defines the on-disk and in-memory representations of every
// Noso record, with Marshal/Unmarshal methods that produce or consume the
// exact byte layout the Pascal node uses.
//
// Sizes (each Pascal `String[N]` occupies N+1 bytes on disk):
//
//	WalletData     626 bytes  (wallet.pkw)
//	SummaryRecord  106 bytes  (sumary.psk)
//	ResumenData     70 bytes  (blchhead.nos)
//	BlockHeader    368 bytes  (BLOCKS/{N}.blk header)
//	Order          562 bytes  (BLOCKS/{N}.blk transactions)
//	GVT            105 bytes  (gvts.psk)
//
// All integers are little-endian. All strings are zero-padded after the
// length byte. No padding between fields ("Packed Record" in Pascal).
package types

import (
	"github.com/noso-project/noso-go/internal/codec"
)

// WalletRecordSize is the on-disk size of one WalletData record in
// wallet.pkw. Source: `WalletData` in `nosowallcon.pas:18-27`.
const WalletRecordSize = 626

// WalletData is one entry of the wallet container `wallet.pkw`.
//
// Field order and capacities are part of the wire format — do NOT reorder
// or change sizes without a hard fork.
type WalletData struct {
	Hash       string // String[40]  — Noso address (e.g. "N4PeJy…Gd")
	Custom     string // String[40]  — alias set via CUSTOM transaction
	PublicKey  string // String[255] — Base64 of uncompressed EC point
	PrivateKey string // String[255] — Base64 of 32-byte scalar
	Balance    int64  // last seen confirmed balance, base units
	Pending    int64  // last seen pending balance
	Score      int64  // token/GVT score
	LastOP     int64  // block height of last operation
}

// Marshal returns the 626-byte little-endian packed encoding of w.
func (w *WalletData) Marshal() []byte {
	buf := make([]byte, WalletRecordSize)
	off := 0
	codec.EncodeShortString(buf[off:], w.Hash, 40)
	off += 41
	codec.EncodeShortString(buf[off:], w.Custom, 40)
	off += 41
	codec.EncodeShortString(buf[off:], w.PublicKey, 255)
	off += 256
	codec.EncodeShortString(buf[off:], w.PrivateKey, 255)
	off += 256
	codec.PutInt64(buf[off:], w.Balance)
	off += 8
	codec.PutInt64(buf[off:], w.Pending)
	off += 8
	codec.PutInt64(buf[off:], w.Score)
	off += 8
	codec.PutInt64(buf[off:], w.LastOP)
	return buf
}

// Unmarshal parses a 626-byte WalletData record from buf. Returns false if
// buf is too short.
func (w *WalletData) Unmarshal(buf []byte) bool {
	if len(buf) < WalletRecordSize {
		return false
	}
	w.Hash = codec.DecodeShortString(buf[0:41], 40)
	w.Custom = codec.DecodeShortString(buf[41:82], 40)
	w.PublicKey = codec.DecodeShortString(buf[82:338], 255)
	w.PrivateKey = codec.DecodeShortString(buf[338:594], 255)
	w.Balance = codec.GetInt64(buf[594:602])
	w.Pending = codec.GetInt64(buf[602:610])
	w.Score = codec.GetInt64(buf[610:618])
	w.LastOP = codec.GetInt64(buf[618:626])
	return true
}
