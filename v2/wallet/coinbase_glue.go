package wallet

import (
	v2crypto "github.com/pasichDev/noso-go/v2/crypto"
)

// v2cryptoSchnorrSign is a thin wrapper so coinbase.go can call into
// crypto without exposing a cycle.
func v2cryptoSchnorrSign(scalar, msg []byte) ([]byte, error) {
	return v2crypto.SchnorrSign(scalar, msg)
}

// v2cryptoVerifyCoinbase recovers the kernel's public key from the
// commit and amount, then verifies the Schnorr signature against it.
//
// Math: a coinbase commit is C = r·G + amount·H. The Schnorr key the
// miner signs with is r (the blinding factor). The verifier doesn't
// know r but knows amount, so it reconstructs r·G = C − amount·H and
// runs Schnorr.Verify against that.
//
// The amount-only commit amount·H is just PedersenCommit(amount, 0) —
// passing a zero blinding factor returns v·H + 0·G = v·H.
func v2cryptoVerifyCoinbase(commit [33]byte, amount int64, msg, sig []byte) bool {
	if amount < 0 {
		return false
	}
	pub, err := pubFromCoinbase(commit, amount)
	if err != nil {
		return false
	}
	return v2crypto.SchnorrVerify(pub, msg, sig)
}

func pubFromCoinbase(commit [33]byte, amount int64) ([33]byte, error) {
	// amount·H = PedersenCommit(amount, all-zero blinding factor).
	// PedersenCommit handles a zero scalar correctly because
	// ScalarBaseMult([0...0]) returns the identity, and Add(p, identity) = p.
	amountCommit, err := v2crypto.PedersenCommit(amount, make([]byte, 32))
	if err != nil {
		return [33]byte{}, err
	}
	return v2crypto.PointSubtract(commit, amountCommit)
}
