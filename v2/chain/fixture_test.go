package chain

import (
	"crypto/sha256"
	"encoding/binary"

	v2crypto "github.com/pasichDev/noso-go/v2/crypto"
	"github.com/pasichDev/noso-go/v2/types"
	"github.com/pasichDev/noso-go/v2/wallet"
)

// sealFixture explicitly constructs version-2 subsidy authorization and full
// body commitments. Unsealed fixture bytes are not accepted implicitly.
func sealFixture(b *types.Block) { sealFixtureClaim(b, 0) }

// sealFixtureClaim is sealFixture with a miner that claims reward + fees + delta.
// delta != 0 builds the block a dishonest miner would try to publish.
func sealFixtureClaim(b *types.Block, delta int64) {
	amount, err := CoinbaseAmount(b)
	if err != nil {
		panic(err)
	}
	if reward := amount + delta; reward > 0 {
		seed := append([]byte("chain test coinbase"), b.Header.PrevHash[:]...)
		seed = binary.BigEndian.AppendUint64(seed, b.Header.Height)
		blind := sha256.Sum256(seed)
		commit, err := v2crypto.PedersenCommit(reward, blind[:])
		if err != nil {
			panic(err)
		}
		rec := wallet.CoinbaseRecord{Height: b.Header.Height, Amount: reward, Blinding: blind, Commit: commit}
		sig, err := wallet.SignCoinbase(b.Header.NetworkMagic, rec)
		if err != nil {
			panic(err)
		}
		b.Outputs = append(b.Outputs, types.Output{Features: types.OutputFeaturesCoinbase, Commit: commit})
		b.Kernels = append(b.Kernels, types.Kernel{Features: types.KernelFeaturesCoinbase, LockHeight: b.Header.Height + types.CoinbaseLock, Excess: commit, ExcessSig: sig})
	}
	types.SetBlockRoots(b)
}
