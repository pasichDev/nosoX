package main

import (
	"crypto/sha256"
	"fmt"

	v2crypto "github.com/noso-project/noso-go/v2/crypto"
	"github.com/noso-project/noso-go/v2/types"
)

// legacyCommitFor recomputes the genesis-bundler Pedersen commitment
// for a legacy balance UTXO. The blinding factor is the public
// deterministic value the bundler used; both nodes and wallets derive
// it independently so no shared secret is needed.
func legacyCommitFor(address string, balance int64) types.Commitment {
	blind := sha256.Sum256([]byte("NosoX legacy blind " + address))
	commit, err := v2crypto.PedersenCommit(balance, blind[:])
	if err != nil {
		panic(fmt.Sprintf("legacyCommitFor: %v", err))
	}
	return commit
}

// gvtCommitFor recomputes the genesis-bundler Pedersen commit for a
// LegacyGVT output.
func gvtCommitFor(slot uint8, owner string) types.Commitment {
	blind := sha256.Sum256([]byte(fmt.Sprintf("NosoX legacy GVT blind %02d %s", slot, owner)))
	commit, err := v2crypto.PedersenCommit(types.GVTBaseValue, blind[:])
	if err != nil {
		panic(fmt.Sprintf("gvtCommitFor: %v", err))
	}
	return commit
}
