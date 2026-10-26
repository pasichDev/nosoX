package chain

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"reflect"
	"testing"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	v1crypto "github.com/pasichDev/noso-go/internal/crypto"
	v2crypto "github.com/pasichDev/noso-go/v2/crypto"
	"github.com/pasichDev/noso-go/v2/legacyclaim"
	"github.com/pasichDev/noso-go/v2/types"
	"github.com/pasichDev/noso-go/v2/wallet"
)

// Scalar 1 is public synthetic test material. No production wallet is accessed.
func legacyV4Fixture(t *testing.T) (*types.Block, *wallet.Wallet) {
	t.Helper()
	secret := make([]byte, 32)
	secret[31] = 1
	key := secp.PrivKeyFromBytes(secret)
	pub := base64.StdEncoding.EncodeToString(key.PubKey().SerializeUncompressed())
	addr, err := v1crypto.AddressFromPublicKey(pub, v1crypto.AddressTypeRegular)
	if err != nil {
		t.Fatal(err)
	}
	w := &wallet.Wallet{Legacy: map[string]wallet.LegacyKeyEntry{addr: {Address: addr, PublicKey: pub, PrivateKey: base64.StdEncoding.EncodeToString(secret)}}}
	g := &types.Block{Header: types.BlockHeader{Version: types.BlockVersion, NetworkMagic: types.NetworkMagicTestnet, Timestamp: baseTime, Difficulty: 1}}
	for _, feature := range []types.OutputFeatures{types.OutputFeaturesLegacy, types.OutputFeaturesLegacyGVT} {
		amount := int64(123456789)
		blind := sha256.Sum256([]byte("NosoX legacy blind " + addr))
		slot := uint8(0)
		if feature == types.OutputFeaturesLegacyGVT {
			amount = types.GVTBaseValue
			slot = 7
			blind = sha256.Sum256([]byte(fmt.Sprintf("NosoX legacy GVT blind %02d %s", slot, addr)))
		}
		commit, err := v2crypto.PedersenCommit(amount, blind[:])
		if err != nil {
			t.Fatal(err)
		}
		g.Outputs = append(g.Outputs, types.Output{Features: feature, Commit: commit, LegacyAddress: addr, LegacyAmount: amount, GVTNumber: slot})
	}
	types.SetBlockRoots(g)
	return g, w
}

func claimV4Block(g *types.Block, tx *types.Transaction) *types.Block {
	b := mineEasy(types.HeaderID(&g.Header), 1)
	b.Header.NetworkMagic = g.Header.NetworkMagic
	b.Inputs = append(b.Inputs, tx.Inputs...)
	b.Outputs = append(b.Outputs, tx.Outputs...)
	b.Kernels = append(b.Kernels, tx.Kernels...)
	types.SetBlockRoots(b)
	return b
}

func resignV4(t *testing.T, in *types.Input, ctx legacyclaim.Context) {
	t.Helper()
	secret := make([]byte, 32)
	secret[31] = 1
	digest, err := legacyclaim.Digest(ctx, legacyclaim.Source{Commitment: in.Commit, Address: in.LegacyAddr, Amount: in.LegacyAmount})
	if err != nil {
		t.Fatal(err)
	}
	in.LegacySig = base64.StdEncoding.EncodeToString(ecdsa.Sign(secp.PrivKeyFromBytes(secret), digest[:]).Serialize())
}

func TestLegacyClaimV4BothBackends(t *testing.T) {
	backendChains(t, func(t *testing.T, c *Chain, dir string) {
		g, w := legacyV4Fixture(t)
		if err := c.LoadOrInit(dir, g); err != nil {
			t.Fatal(err)
		}
		ctx := wallet.LegacyClaimContext{Network: g.Header.NetworkMagic, Genesis: types.HeaderID(&g.Header)}
		tx, _, err := w.BuildLegacyClaimV4(ctx, g.Outputs[0])
		if err != nil {
			t.Fatal(err)
		}
		gvt, _, err := w.BuildGVTRedeemV4(ctx, g.Outputs[1])
		if err != nil {
			t.Fatal(err)
		}
		if err := c.ValidateTransaction(tx); err != nil {
			t.Fatalf("regular admission: %v", err)
		}
		if err := c.ValidateTransaction(gvt); err != nil {
			t.Fatalf("GVT admission: %v", err)
		}
		before := snapshot(t, c)
		mutations := map[string]func(*types.Block){
			"missing key": func(b *types.Block) { b.Inputs[0].LegacyPubKey = "" },
			"wrong key": func(b *types.Block) {
				raw := make([]byte, 32)
				raw[31] = 2
				b.Inputs[0].LegacyPubKey = base64.StdEncoding.EncodeToString(secp.PrivKeyFromBytes(raw).PubKey().SerializeUncompressed())
			},
			"missing signature":   func(b *types.Block) { b.Inputs[0].LegacySig = "" },
			"wrong signature":     func(b *types.Block) { b.Inputs[0].LegacySig = "MAA=" },
			"missing destination": func(b *types.Block) { b.Inputs[0].LegacyOutputID = types.Hash{} },
			"wrong destination":   func(b *types.Block) { b.Inputs[0].LegacyOutputID[0] ^= 1 },
			"wrong kernel":        func(b *types.Block) { b.Inputs[0].LegacyKernelID[0] ^= 1 },
			"duplicate source":    func(b *types.Block) { b.Inputs = append(b.Inputs, b.Inputs[0]) },
			"shared leg": func(b *types.Block) {
				in := gvt.Inputs[0]
				in.LegacyOutputID = b.Inputs[0].LegacyOutputID
				in.LegacyKernelID = b.Inputs[0].LegacyKernelID
				b.Inputs = append(b.Inputs, in)
			},
			"fee":             func(b *types.Block) { b.Kernels[1].Fee = 1 },
			"lock":            func(b *types.Block) { b.Kernels[1].LockHeight = 1 },
			"bad Schnorr":     func(b *types.Block) { b.Kernels[1].ExcessSig[40] ^= 1 },
			"metadata amount": func(b *types.Block) { b.Inputs[0].LegacyAmount++ },
			"network": func(b *types.Block) {
				cx := legacyclaim.Context{Network: ctx.Network + 1, Genesis: ctx.Genesis, DestinationTransaction: legacyclaim.DestinationDigest(b.Inputs[0].LegacyOutputID, b.Inputs[0].LegacyKernelID)}
				resignV4(t, &b.Inputs[0], cx)
			},
			"genesis": func(b *types.Block) {
				other := ctx.Genesis
				other[0] ^= 1
				cx := legacyclaim.Context{Network: ctx.Network, Genesis: other, DestinationTransaction: legacyclaim.DestinationDigest(b.Inputs[0].LegacyOutputID, b.Inputs[0].LegacyKernelID)}
				resignV4(t, &b.Inputs[0], cx)
			},
			"destination signature": func(b *types.Block) {
				d := legacyclaim.DestinationDigest(b.Inputs[0].LegacyOutputID, b.Inputs[0].LegacyKernelID)
				d[0] ^= 1
				resignV4(t, &b.Inputs[0], legacyclaim.Context{Network: ctx.Network, Genesis: ctx.Genesis, DestinationTransaction: d})
			},
			"inflation": func(b *types.Block) {
				out, err := wallet.NewPlainOutput(g.Outputs[0].LegacyAmount + 1)
				if err != nil {
					t.Fatal(err)
				}
				b.Outputs[1] = out.Output
				b.Inputs[0].LegacyOutputID = types.OutputID(&b.Outputs[1])
				resignV4(t, &b.Inputs[0], legacyclaim.Context{Network: ctx.Network, Genesis: ctx.Genesis, DestinationTransaction: legacyclaim.DestinationDigest(b.Inputs[0].LegacyOutputID, b.Inputs[0].LegacyKernelID)})
			},
			"unreferenced claim kernel": func(b *types.Block) { b.Kernels = append(b.Kernels, gvt.Kernels[0]) },
		}
		for name, mutate := range mutations {
			t.Run(name, func(t *testing.T) {
				b := cloneBlock(claimV4Block(g, tx))
				mutate(b)
				types.SetBlockRoots(b)
				if err := c.AddBlock(b); err == nil {
					t.Fatal("malicious claim accepted")
				}
				if !reflect.DeepEqual(before, snapshot(t, c)) {
					t.Fatal("rejection changed state")
				}
			})
		}
		combined := &types.Transaction{Inputs: append(append([]types.Input{}, tx.Inputs...), gvt.Inputs...), Outputs: append(append([]types.Output{}, tx.Outputs...), gvt.Outputs...), Kernels: append(append([]types.Kernel{}, tx.Kernels...), gvt.Kernels...)}
		b := claimV4Block(g, combined)
		if err := c.AddBlock(b); err != nil {
			t.Fatalf("valid two-leg block: %v", err)
		}
		for _, source := range g.Outputs {
			if c.store.HasUTXO(source.Commit) {
				t.Fatal("source not consumed")
			}
		}
		if err := c.ValidateTransaction(tx); err == nil {
			t.Fatal("claim replay admitted")
		}
		replay := mineEasy(types.HeaderID(&b.Header), 2)
		replay.Header.NetworkMagic = ctx.Network
		replay.Inputs = tx.Inputs
		replay.Outputs = append(replay.Outputs, tx.Outputs...)
		replay.Kernels = append(replay.Kernels, tx.Kernels...)
		types.SetBlockRoots(replay)
		if err := c.AddBlock(replay); err == nil {
			t.Fatal("claim replay accepted")
		}
		if err := c.LoadOrInit(dir, g); err != nil {
			t.Fatalf("verified restart: %v", err)
		}
		// A longer empty fork restores both trusted sources. The old claim can
		// be mined again only because the canonical spending block was undone.
		f1 := mineEasy(types.HeaderID(&g.Header), 1)
		f1.Header.NetworkMagic = ctx.Network
		f1.Header.Timestamp++
		types.SetBlockRoots(f1)
		f2 := mineEasy(types.HeaderID(&f1.Header), 2)
		f2.Header.NetworkMagic = ctx.Network
		types.SetBlockRoots(f2)
		if err := c.ReorgTo([]*types.Block{f1, f2}); err != nil {
			t.Fatalf("claim undo reorg: %v", err)
		}
		for _, source := range g.Outputs {
			if !c.store.HasUTXO(source.Commit) {
				t.Fatal("reorg failed to restore source")
			}
		}
		if err := c.ValidateTransaction(tx); err != nil {
			t.Fatalf("restored source cannot be claimed: %v", err)
		}
	})
}

func TestLegacyClaimV4DurableRestart(t *testing.T) {
	for _, backend := range []string{"memory", "badger"} {
		t.Run(backend, func(t *testing.T) {
			dir := t.TempDir()
			open := func() *Chain {
				if backend == "memory" {
					return NewMemory()
				}
				c, err := NewBadger(dir)
				if err != nil {
					t.Fatal(err)
				}
				return c
			}
			g, w := legacyV4Fixture(t)
			ctx := wallet.LegacyClaimContext{Network: g.Header.NetworkMagic, Genesis: types.HeaderID(&g.Header)}
			tx, _, err := w.BuildLegacyClaimV4(ctx, g.Outputs[0])
			if err != nil {
				t.Fatal(err)
			}
			c := open()
			if err := c.LoadOrInit(dir, g); err != nil {
				c.Close()
				t.Fatal(err)
			}
			b := claimV4Block(g, tx)
			if err := c.AddBlock(b); err != nil {
				c.Close()
				t.Fatal(err)
			}
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
			restored := open()
			defer restored.Close()
			if err := restored.LoadOrInit(dir, g); err != nil {
				t.Fatal(err)
			}
			stored, ok := restored.BlockByHeight(1)
			if !ok || !reflect.DeepEqual(stored.Inputs, tx.Inputs) {
				t.Fatal("ownership fields failed round trip")
			}
			if restored.store.HasUTXO(g.Outputs[0].Commit) || !restored.store.HasUTXO(tx.Outputs[0].Commit) {
				t.Fatal("claim state did not survive restart")
			}
			if err := restored.ValidateTransaction(tx); err == nil {
				t.Fatal("replay admitted after restart")
			}
		})
	}
}
