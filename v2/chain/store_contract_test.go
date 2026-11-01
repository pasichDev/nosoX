package chain

import (
	"github.com/dgraph-io/badger/v4"
	"reflect"
	"testing"

	v2crypto "github.com/pasichDev/nosoX/v2/crypto"
	"github.com/pasichDev/nosoX/v2/types"
)

func storePoint(t *testing.T, n byte) types.Commitment {
	t.Helper()
	var scalar [32]byte
	scalar[31] = n
	c, err := v2crypto.PublicFromScalar(scalar[:])
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// These are storage-only fixtures: the initial raw output is explicit,
// while subsequent raw deltas intentionally do not claim subsidy/proof/signature
// validity. The Store must protect its indices even from a mistaken trusted caller.
func TestSecurityStoreRejectsImpossibleDeltas(t *testing.T) {
	mutations := map[string]func(*types.Block, types.Commitment, types.Commitment, types.Commitment, types.Kernel){
		"missing input": func(b *types.Block, a, existing, fresh types.Commitment, k types.Kernel) {
			b.Inputs = []types.Input{{Commit: fresh}}
		},
		"duplicate input": func(b *types.Block, a, existing, fresh types.Commitment, k types.Kernel) {
			b.Inputs = []types.Input{{Commit: existing}, {Commit: existing}}
		},
		"input feature": func(b *types.Block, a, existing, fresh types.Commitment, k types.Kernel) {
			b.Inputs = []types.Input{{Commit: existing, Features: types.OutputFeaturesCoinbase}}
		},
		"duplicate output": func(b *types.Block, a, existing, fresh types.Commitment, k types.Kernel) {
			b.Outputs = []types.Output{{Commit: fresh}, {Commit: fresh}}
		},
		"unspent output": func(b *types.Block, a, existing, fresh types.Commitment, k types.Kernel) {
			b.Outputs = []types.Output{{Commit: existing}}
		},
		"spent historical output": func(b *types.Block, a, existing, fresh types.Commitment, k types.Kernel) {
			b.Outputs = []types.Output{{Commit: a}}
		},
		"same input output": func(b *types.Block, a, existing, fresh types.Commitment, k types.Kernel) {
			b.Inputs = []types.Input{{Commit: existing}}
			b.Outputs = []types.Output{{Commit: existing}}
		},
		"duplicate kernel": func(b *types.Block, a, existing, fresh types.Commitment, k types.Kernel) {
			k.Excess = fresh
			b.Kernels = []types.Kernel{k, k}
		},
		"historical kernel": func(b *types.Block, a, existing, fresh types.Commitment, k types.Kernel) {
			b.Kernels = []types.Kernel{k}
		},
		"wrong parent": func(b *types.Block, a, existing, fresh types.Commitment, k types.Kernel) { b.Header.PrevHash[0] ^= 1 },
		"wrong height": func(b *types.Block, a, existing, fresh types.Commitment, k types.Kernel) { b.Header.Height++ },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			backendChains(t, func(t *testing.T, c *Chain, dir string) {
				a, existing, fresh := storePoint(t, 1), storePoint(t, 2), storePoint(t, 3)
				g := easyGenesisBlock(t)
				g.Outputs = []types.Output{{Features: types.OutputFeaturesPlain, Commit: a}}
				types.SetBlockRoots(g)
				if err := c.store.WriteBlock(g); err != nil {
					t.Fatal(err)
				}
				kernel := types.Kernel{Excess: storePoint(t, 4)}
				first := &types.Block{Header: easyHeader(types.HeaderID(&g.Header), 1), Inputs: []types.Input{{Features: types.OutputFeaturesPlain, Commit: a}}, Outputs: []types.Output{{Commit: existing}}, Kernels: []types.Kernel{kernel}}
				if err := c.store.WriteBlock(first); err != nil {
					t.Fatal(err)
				}
				before := snapshot(t, c)
				candidate := &types.Block{Header: easyHeader(types.HeaderID(&first.Header), 2), Outputs: []types.Output{{Commit: fresh}}}
				mutate(candidate, a, existing, fresh, kernel)
				if err := c.store.WriteBlock(candidate); err == nil {
					t.Fatal("raw store accepted impossible delta")
				}
				if !reflect.DeepEqual(before, snapshot(t, c)) {
					t.Fatal("failed raw store write changed state")
				}
				if err := c.store.ReplaceChain([]*types.Block{g, first, candidate}); err == nil {
					t.Fatal("raw replacement accepted impossible delta")
				}
				if !reflect.DeepEqual(before, snapshot(t, c)) {
					t.Fatal("failed raw replacement changed state")
				}

			})
		})
	}
}

func rawBadgerEntries(t *testing.T, s *BadgerStore) map[string][]byte {
	t.Helper()
	entries := map[string][]byte{}
	if err := s.view(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			if err := item.Value(func(raw []byte) error { entries[string(item.KeyCopy(nil))] = append([]byte(nil), raw...); return nil }); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return entries
}

func TestSecurityStoreBadgerDecodeFailureUnchanged(t *testing.T) {
	for _, field := range []string{"utxo", "tip"} {
		t.Run(field, func(t *testing.T) {
			s, err := OpenBadger(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			commit := storePoint(t, 1)
			g := easyGenesisBlock(t)
			g.Outputs = []types.Output{{Features: types.OutputFeaturesPlain, Commit: commit}}
			types.SetBlockRoots(g)
			if err := s.WriteBlock(g); err != nil {
				t.Fatal(err)
			}
			key := []byte{kTip}
			if field == "utxo" {
				key = append([]byte{kUTXO}, commit[:]...)
			}
			if err := s.mutate(func(txn *stageTxn) error { return txn.Set(key, []byte("corrupt")) }); err != nil {
				t.Fatal(err)
			}
			before := rawBadgerEntries(t, s)
			b := &types.Block{Header: easyHeader(types.HeaderID(&g.Header), 1), Inputs: []types.Input{{Features: types.OutputFeaturesPlain, Commit: commit}}}
			if err := s.WriteBlock(b); err == nil {
				t.Fatal("decode/read error authorized a delta")
			}
			if !reflect.DeepEqual(before, rawBadgerEntries(t, s)) {
				t.Fatal("decode failure changed durable state")
			}
		})
	}
}
