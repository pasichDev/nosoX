package types

import "github.com/noso-project/noso-go/internal/codec"

// ResumenDataSize is the size of one ResumenData record in blchhead.nos.
// Source: `nosoheaders.pas:18-22`.
const ResumenDataSize = 70

// ResumenData is a per-block fingerprint stored in the headers file. The
// file is append-only; one record is written after every finalized block.
type ResumenData struct {
	Block     int32  // block number
	BlockHash string // String[32] — MD5 of the .blk file
	SumHash   string // String[32] — MD5 of sumary.psk at this height
}

func (r *ResumenData) Marshal() []byte {
	buf := make([]byte, ResumenDataSize)
	codec.PutInt32(buf[0:4], r.Block)
	codec.EncodeShortString(buf[4:37], r.BlockHash, 32)
	codec.EncodeShortString(buf[37:70], r.SumHash, 32)
	return buf
}

func (r *ResumenData) Unmarshal(buf []byte) bool {
	if len(buf) < ResumenDataSize {
		return false
	}
	r.Block = codec.GetInt32(buf[0:4])
	r.BlockHash = codec.DecodeShortString(buf[4:37], 32)
	r.SumHash = codec.DecodeShortString(buf[37:70], 32)
	return true
}
