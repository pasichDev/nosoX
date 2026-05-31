package types

import (
	"bytes"
	"testing"
)

func TestRecordSizes(t *testing.T) {
	// These sizes are part of the on-disk format. Any change breaks every
	// existing wallet.pkw / sumary.psk / .blk file.
	cases := []struct {
		name string
		got  int
		want int
	}{
		{"WalletData", WalletRecordSize, 626},
		{"SummaryRecord", SummaryRecordSize, 106},
		{"ResumenData", ResumenDataSize, 70},
		{"BlockHeader", BlockHeaderSize, 368},
		{"Order", OrderSize, 562},
		{"GVT", GVTSize, 105},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s size = %d, want %d", c.name, c.got, c.want)
		}
	}
}

func TestWalletRoundTrip(t *testing.T) {
	in := WalletData{
		Hash:       "N4PeJyqj8diSXnfhxSQdLpo8ddXTaGd",
		Custom:     "treasury",
		PublicKey:  "BPubKey88CharsBase64ExpectedHereBut" + "OkayShorter",
		PrivateKey: "BPriv44CharsBase64ExpectedHere",
		Balance:    1_030_390_730_000,
		Pending:    0,
		Score:      0,
		LastOP:     0,
	}
	raw := in.Marshal()
	if len(raw) != WalletRecordSize {
		t.Fatalf("marshal size = %d", len(raw))
	}
	var out WalletData
	if !out.Unmarshal(raw) {
		t.Fatal("unmarshal returned false")
	}
	if out != in {
		t.Fatalf("round-trip mismatch:\n got %+v\n want %+v", out, in)
	}
}

func TestSummaryRoundTrip(t *testing.T) {
	in := SummaryRecord{
		Hash:    "N4PeJyqj8diSXnfhxSQdLpo8ddXTaGd",
		Custom:  "",
		Balance: 1_030_390_730_000,
		Score:   0,
		LastOP:  0,
	}
	raw := in.Marshal()
	var out SummaryRecord
	if !out.Unmarshal(raw) {
		t.Fatal("unmarshal returned false")
	}
	if out != in {
		t.Fatalf("round-trip mismatch:\n got %+v\n want %+v", out, in)
	}
	// First length byte must be the actual hash length.
	if int(raw[0]) != len(in.Hash) {
		t.Errorf("hash length byte = %d, want %d", raw[0], len(in.Hash))
	}
	// Balance must be at offset 82, little-endian. Premine = 0xEFE812CD10.
	want := []byte{0x10, 0xcd, 0x12, 0xe8, 0xef, 0x00, 0x00, 0x00}
	if !bytes.Equal(raw[82:90], want) {
		t.Errorf("balance bytes = % x, want % x", raw[82:90], want)
	}
}

func TestOrderRoundTrip(t *testing.T) {
	in := Order{
		Block:      59238,
		OrderID:    "ORabcdefghij",
		OrderLines: 1,
		OrderType:  OrderTypeTransfer,
		TimeStamp:  1_700_000_000,
		Reference:  "null",
		TrxLine:    1,
		Sender:     "BPubkeyBase64==",
		Address:    "Nsenderxxxxxxxxxxxxxxxxxxxxxxxxx",
		Receiver:   "Nreceiverxxxxxxxxxxxxxxxxxxxxxxx",
		AmmountFee: 1_000_000,
		AmmountTrf: 100_000_000,
		Signature:  "BSigBase64==",
		TrfrID:     "tRxxxxxxxxxxxxxxxxxxxx",
	}
	raw := in.Marshal()
	var out Order
	if !out.Unmarshal(raw) {
		t.Fatal("unmarshal returned false")
	}
	if out != in {
		t.Fatalf("round-trip mismatch:\n got %+v\n want %+v", out, in)
	}
}

func TestBlockHeaderRoundTrip(t *testing.T) {
	in := BlockHeader{
		Number:        59238,
		TimeStart:     1_615_132_800,
		TimeEnd:       1_615_133_400,
		TimeTotal:     600,
		TimeLast20:    600,
		TrxTotales:    3,
		Difficult:     12,
		TargetHash:    "0000000000000000",
		Solution:      "solution-data-here",
		LastBlockHash: "ABCDEF1234567890",
		NxtBlkDiff:    12,
		AccountMiner:  "Nminerxxxxxxxxxxxxxxxxxxxxxxx",
		MinerFee:      1_500_000,
		Reward:        5_000_000_000,
	}
	raw := in.Marshal()
	var out BlockHeader
	if !out.Unmarshal(raw) {
		t.Fatal("unmarshal returned false")
	}
	if out != in {
		t.Fatalf("round-trip mismatch:\n got %+v\n want %+v", out, in)
	}
}

func TestHeadersRoundTrip(t *testing.T) {
	in := ResumenData{Block: 59238, BlockHash: "ABCDEF", SumHash: "123456"}
	raw := in.Marshal()
	var out ResumenData
	if !out.Unmarshal(raw) {
		t.Fatal("unmarshal returned false")
	}
	if out != in {
		t.Fatalf("round-trip mismatch")
	}
}

func TestGVTRoundTrip(t *testing.T) {
	in := GVT{
		Number:  "07",
		Owner:   "Nownerxxxxxxxxxxxxxxxxxxxxxxx",
		Hash:    "tokenhashvalue",
		Control: 1,
	}
	raw := in.Marshal()
	var out GVT
	if !out.Unmarshal(raw) {
		t.Fatal("unmarshal returned false")
	}
	if out != in {
		t.Fatalf("round-trip mismatch")
	}
}
