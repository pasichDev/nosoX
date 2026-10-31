package chain

import (
	"path/filepath"
	"testing"
)

func TestStreamingReplayMatchesAndRejectsCorruptState(t *testing.T) {
	for _, change := range []string{"none", "missing", "extra", "value", "block", "oversized block"} {
		t.Run(change, func(t *testing.T) {
			parent := t.TempDir()
			c, err := NewBadger(filepath.Join(parent, "source"))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			g := easyGenesisBlock(t)
			if err := c.LoadOrInit(parent, g); err != nil {
				t.Fatal(err)
			}
			blocks := appendBlocks(t, c, 1, 4)
			s := c.store.(*BadgerStore)
			key := append([]byte{kUTXO}, blocks[0].Outputs[0].Commit[:]...)
			if change != "none" {
				err := s.mutate(func(txn *stageTxn) error {
					switch change {
					case "missing":
						return txn.Delete(key)
					case "extra":
						return txn.Set([]byte("extra persisted key"), []byte{1})
					case "value":
						return txn.Set(key, []byte("corrupt"))
					case "block":
						b := cloneBlock(blocks[0])
						b.Kernels[0].ExcessSig[0] ^= 1
						raw, err := encodeBlock(b)
						if err != nil {
							return err
						}
						return txn.Set(heightKey(kBlock, 1), raw)
					case "oversized block":
						return txn.Set(heightKey(kBlock, 1), make([]byte, 2*MaxBlockBodyBytes+4097))
					}
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}
			}
			err = c.streamingVerifyHistory(s, g)
			if change == "none" && err != nil {
				t.Fatal(err)
			}
			if change != "none" && err == nil {
				t.Fatal("accepted corrupt canonical state")
			}
			leftovers, err := filepath.Glob(filepath.Join(parent, ".nosox-replay-*"))
			if err != nil || len(leftovers) != 0 {
				t.Fatalf("scratch cleanup: %v %v", leftovers, err)
			}
		})
	}
}

func TestStreamingReplayPinsTrustedGenesis(t *testing.T) {
	c, err := NewBadger(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	g := easyGenesisBlock(t)
	if err := c.store.WriteBlock(g); err != nil {
		t.Fatal(err)
	}
	other := cloneBlock(g)
	other.Header.Nonce++
	if err := c.streamingVerifyHistory(c.store.(*BadgerStore), other); err == nil {
		t.Fatal("accepted different trusted genesis")
	}
}
