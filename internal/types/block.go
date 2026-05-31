package types

import "github.com/noso-project/noso-go/internal/codec"

// BlockHeaderSize is the on-disk size of BlockHeaderData. Source:
// `nosoblock.pas:25-40`.
//
//	Number          int64    8
//	TimeStart       int64    8
//	TimeEnd         int64    8
//	TimeTotal       int32    4
//	TimeLast20      int32    4
//	TrxTotales      int32    4
//	Difficult       int32    4
//	TargetHash      Str[32] 33
//	Solution        Str[200] 201
//	LastBlockHash   Str[32] 33
//	NxtBlkDiff      int32    4
//	AccountMiner    Str[40] 41
//	MinerFee        int64    8
//	Reward          int64    8
//	                       ----
//	                        368
const BlockHeaderSize = 368

// BlockHeader is the fixed-size header at the start of every .blk file.
//
// Semantics by block range:
//
//   - Blocks 1..52999: `Difficult = 0` (no PoW required during early phase).
//   - Blocks 53000+:   `Difficult` is repurposed to hold the PoS count for
//     that block.
//   - Block 0 (genesis): Solution is empty, LastBlockHash is the literal
//     string "NOSO GENESYS BLOCK", TimeStart=1531896783.
type BlockHeader struct {
	Number        int64
	TimeStart     int64
	TimeEnd       int64
	TimeTotal     int32
	TimeLast20    int32
	TrxTotales    int32
	Difficult     int32
	TargetHash    string // String[32]
	Solution      string // String[200] (180 bytes typically used)
	LastBlockHash string // String[32]  — MD5 of the previous block's file
	NxtBlkDiff    int32
	AccountMiner  string // String[40]  — winning miner address
	MinerFee      int64
	Reward        int64
}

func (h *BlockHeader) Marshal() []byte {
	buf := make([]byte, BlockHeaderSize)
	off := 0
	codec.PutInt64(buf[off:], h.Number)
	off += 8
	codec.PutInt64(buf[off:], h.TimeStart)
	off += 8
	codec.PutInt64(buf[off:], h.TimeEnd)
	off += 8
	codec.PutInt32(buf[off:], h.TimeTotal)
	off += 4
	codec.PutInt32(buf[off:], h.TimeLast20)
	off += 4
	codec.PutInt32(buf[off:], h.TrxTotales)
	off += 4
	codec.PutInt32(buf[off:], h.Difficult)
	off += 4
	codec.EncodeShortString(buf[off:], h.TargetHash, 32)
	off += 33
	codec.EncodeShortString(buf[off:], h.Solution, 200)
	off += 201
	codec.EncodeShortString(buf[off:], h.LastBlockHash, 32)
	off += 33
	codec.PutInt32(buf[off:], h.NxtBlkDiff)
	off += 4
	codec.EncodeShortString(buf[off:], h.AccountMiner, 40)
	off += 41
	codec.PutInt64(buf[off:], h.MinerFee)
	off += 8
	codec.PutInt64(buf[off:], h.Reward)
	return buf
}

func (h *BlockHeader) Unmarshal(buf []byte) bool {
	if len(buf) < BlockHeaderSize {
		return false
	}
	h.Number = codec.GetInt64(buf[0:8])
	h.TimeStart = codec.GetInt64(buf[8:16])
	h.TimeEnd = codec.GetInt64(buf[16:24])
	h.TimeTotal = codec.GetInt32(buf[24:28])
	h.TimeLast20 = codec.GetInt32(buf[28:32])
	h.TrxTotales = codec.GetInt32(buf[32:36])
	h.Difficult = codec.GetInt32(buf[36:40])
	h.TargetHash = codec.DecodeShortString(buf[40:73], 32)
	h.Solution = codec.DecodeShortString(buf[73:274], 200)
	h.LastBlockHash = codec.DecodeShortString(buf[274:307], 32)
	h.NxtBlkDiff = codec.GetInt32(buf[307:311])
	h.AccountMiner = codec.DecodeShortString(buf[311:352], 40)
	h.MinerFee = codec.GetInt64(buf[352:360])
	h.Reward = codec.GetInt64(buf[360:368])
	return true
}
