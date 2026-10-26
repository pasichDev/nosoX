package types

import "github.com/pasichDev/noso-go/internal/codec"

// SummaryRecordSize is the on-disk size of one TSummaryData record in
// sumary.psk. Source: `nosounit.pas:18-24`.
const SummaryRecordSize = 106

// SummaryRecord is one account-state entry in `sumary.psk`. Records are
// laid out back-to-back with no file header.
type SummaryRecord struct {
	Hash    string // String[40] — Noso address
	Custom  string // String[40] — optional alias
	Balance int64  // confirmed balance, base units (8 decimals)
	Score   int64  // token/GVT score
	LastOP  int64  // block height of last operation
}

// Marshal returns the 106-byte packed encoding.
func (s *SummaryRecord) Marshal() []byte {
	buf := make([]byte, SummaryRecordSize)
	codec.EncodeShortString(buf[0:41], s.Hash, 40)
	codec.EncodeShortString(buf[41:82], s.Custom, 40)
	codec.PutInt64(buf[82:90], s.Balance)
	codec.PutInt64(buf[90:98], s.Score)
	codec.PutInt64(buf[98:106], s.LastOP)
	return buf
}

// Unmarshal parses one record from buf. Returns false if buf is too short.
func (s *SummaryRecord) Unmarshal(buf []byte) bool {
	if len(buf) < SummaryRecordSize {
		return false
	}
	s.Hash = codec.DecodeShortString(buf[0:41], 40)
	s.Custom = codec.DecodeShortString(buf[41:82], 40)
	s.Balance = codec.GetInt64(buf[82:90])
	s.Score = codec.GetInt64(buf[90:98])
	s.LastOP = codec.GetInt64(buf[98:106])
	return true
}
