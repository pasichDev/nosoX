package types

import "github.com/noso-project/noso-go/internal/codec"

// OrderSize is the on-disk size of TOrderData. Source:
// `nosogeneral.pas:26-41`.
//
//	Block       int32     4
//	OrderID     Str[64]  65
//	OrderLines  int32     4
//	OrderType   Str[6]    7
//	TimeStamp   int64     8
//	Reference   Str[64]  65
//	TrxLine     int32     4
//	Sender      Str[120] 121
//	Address     Str[40]  41
//	Receiver    Str[40]  41
//	AmmountFee  int64     8
//	AmmountTrf  int64     8
//	Signature   Str[120] 121
//	TrfrID      Str[64]  65
//	                   ----
//	                    562
const OrderSize = 562

// OrderType constants used in Pascal as 4..6-char string literals.
const (
	OrderTypeTransfer       = "TRFR"
	OrderTypeCustom         = "CUSTOM"
	OrderTypeSendGVT        = "SNDGVT"
	OrderTypeProjectPayment = "PROJCT"
)

// Order is one transaction record. It is shipped on the wire as a
// space-separated text line (the protocol-line form) and also serialized
// on disk in this packed-record form inside .blk files.
type Order struct {
	Block      int32
	OrderID    string // String[64]
	OrderLines int32  // 1 for single-line orders
	OrderType  string // String[6]
	TimeStamp  int64
	Reference  string // String[64]  — memo, or GVT number for SNDGVT
	TrxLine    int32  // line number within a multi-line ORDER
	Sender     string // String[120] — sender's Base64 public key
	Address    string // String[40]  — sender's address (hash derived)
	Receiver   string // String[40]  — recipient address
	AmmountFee int64  // base units; Pascal misspells "Amount" as "Ammount"
	AmmountTrf int64  // base units transferred
	Signature  string // String[120] — Base64 DER ECDSA signature
	TrfrID     string // String[64]  — TransferHash of canonical sign-input
}

func (o *Order) Marshal() []byte {
	buf := make([]byte, OrderSize)
	off := 0
	codec.PutInt32(buf[off:], o.Block)
	off += 4
	codec.EncodeShortString(buf[off:], o.OrderID, 64)
	off += 65
	codec.PutInt32(buf[off:], o.OrderLines)
	off += 4
	codec.EncodeShortString(buf[off:], o.OrderType, 6)
	off += 7
	codec.PutInt64(buf[off:], o.TimeStamp)
	off += 8
	codec.EncodeShortString(buf[off:], o.Reference, 64)
	off += 65
	codec.PutInt32(buf[off:], o.TrxLine)
	off += 4
	codec.EncodeShortString(buf[off:], o.Sender, 120)
	off += 121
	codec.EncodeShortString(buf[off:], o.Address, 40)
	off += 41
	codec.EncodeShortString(buf[off:], o.Receiver, 40)
	off += 41
	codec.PutInt64(buf[off:], o.AmmountFee)
	off += 8
	codec.PutInt64(buf[off:], o.AmmountTrf)
	off += 8
	codec.EncodeShortString(buf[off:], o.Signature, 120)
	off += 121
	codec.EncodeShortString(buf[off:], o.TrfrID, 64)
	return buf
}

func (o *Order) Unmarshal(buf []byte) bool {
	if len(buf) < OrderSize {
		return false
	}
	o.Block = codec.GetInt32(buf[0:4])
	o.OrderID = codec.DecodeShortString(buf[4:69], 64)
	o.OrderLines = codec.GetInt32(buf[69:73])
	o.OrderType = codec.DecodeShortString(buf[73:80], 6)
	o.TimeStamp = codec.GetInt64(buf[80:88])
	o.Reference = codec.DecodeShortString(buf[88:153], 64)
	o.TrxLine = codec.GetInt32(buf[153:157])
	o.Sender = codec.DecodeShortString(buf[157:278], 120)
	o.Address = codec.DecodeShortString(buf[278:319], 40)
	o.Receiver = codec.DecodeShortString(buf[319:360], 40)
	o.AmmountFee = codec.GetInt64(buf[360:368])
	o.AmmountTrf = codec.GetInt64(buf[368:376])
	o.Signature = codec.DecodeShortString(buf[376:497], 120)
	o.TrfrID = codec.DecodeShortString(buf[497:562], 64)
	return true
}
