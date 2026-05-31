package p2p

import (
	"bytes"
	"encoding/gob"
	"testing"

	"github.com/noso-project/noso-go/v2/types"
)

// FuzzBlockDecode feeds arbitrary bytes to the gob block decoder. A
// successful crash here means a malicious peer can DoS gossipsub
// consumers by sending malformed payloads.
func FuzzBlockDecode(f *testing.F) {
	// Seed with a real block.
	good := &types.Block{Header: types.BlockHeader{Height: 1, Nonce: 7}}
	var buf bytes.Buffer
	_ = gob.NewEncoder(&buf).Encode(good)
	f.Add(buf.Bytes())
	f.Add([]byte{0xff, 0x00, 0x01})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = decodeBlockMsg(raw)
	})
}

// FuzzTxDecode does the same for transactions.
func FuzzTxDecode(f *testing.F) {
	good := &types.Transaction{}
	var buf bytes.Buffer
	_ = gob.NewEncoder(&buf).Encode(good)
	f.Add(buf.Bytes())
	f.Add([]byte{0xfe})
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = decodeTxMsg(raw)
	})
}
