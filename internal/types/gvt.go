package types

import "github.com/pasichDev/noso-go/internal/codec"

// GVTSize is the on-disk size of TGVT. Source: `nosogvts.pas:11-16`.
const GVTSize = 105

// GVT is one governance/voting token in `gvts.psk`. Maximum 100 tokens
// (numbered "00".."99"), each owned by exactly one address. Only
// AdminPubKey can transfer them via SNDGVT.
type GVT struct {
	Number  string // String[2]   — token number "00".."99"
	Owner   string // String[32]  — owner address
	Hash    string // String[64]  — token ID hash
	Control int32  // control flags (rarely used)
}

func (g *GVT) Marshal() []byte {
	buf := make([]byte, GVTSize)
	codec.EncodeShortString(buf[0:3], g.Number, 2)
	codec.EncodeShortString(buf[3:36], g.Owner, 32)
	codec.EncodeShortString(buf[36:101], g.Hash, 64)
	codec.PutInt32(buf[101:105], g.Control)
	return buf
}

func (g *GVT) Unmarshal(buf []byte) bool {
	if len(buf) < GVTSize {
		return false
	}
	g.Number = codec.DecodeShortString(buf[0:3], 2)
	g.Owner = codec.DecodeShortString(buf[3:36], 32)
	g.Hash = codec.DecodeShortString(buf[36:101], 64)
	g.Control = codec.GetInt32(buf[101:105])
	return true
}
