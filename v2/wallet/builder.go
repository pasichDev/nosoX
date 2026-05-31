// builder.go implements the actual Transaction construction logic
// the CLI exposes via `wallet claim`, `wallet pay`, `wallet receive`,
// and `wallet finalize`, plus the GVT operations.
//
// The builder is deliberately conservative:
//
//   - Inputs and outputs are tracked separately so a caller can audit
//     the conservation equation before broadcasting.
//   - Per-output blinding factors are sampled inside the builder; the
//     caller never sees them. The sum of input blindings minus output
//     blindings becomes the kernel-excess scalar.
//   - Schnorr signatures on the kernel use the constant-time path
//     (SchnorrSignConstantTime via SchnorrSign).
//
// This file is the integration point between the Slatepack codec
// (slatepack.go), the legacy claim helpers (wallet.go), and the
// constant-time crypto primitives in v2/crypto.

package wallet

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"

	v2crypto "github.com/noso-project/noso-go/v2/crypto"
	"github.com/noso-project/noso-go/v2/types"
)

// BlindingFactor is a 32-byte scalar used as the Pedersen blinding for
// an output. The wallet stores these alongside the output so it can
// later spend the output by exposing the blinding factor in the
// kernel excess.
type BlindingFactor [32]byte

// PlainOutput packages a fresh Pedersen output ready to slot into a
// Transaction. The wallet keeps the blinding factor in its own state
// (CoinbaseStore-style) so it can spend the output later.
type PlainOutput struct {
	Output   types.Output
	Blinding BlindingFactor
	Value    int64
}

// NewPlainOutput crafts a Plain output for `value` base units with a
// fresh random blinding factor. Both the commitment and range proof
// are populated; the caller plugs the result into a Transaction.
func NewPlainOutput(value int64) (PlainOutput, error) {
	if value < 0 {
		return PlainOutput{}, errors.New("wallet: negative output value")
	}
	var blind BlindingFactor
	if _, err := rand.Read(blind[:]); err != nil {
		return PlainOutput{}, err
	}
	commit, err := v2crypto.PedersenCommit(value, blind[:])
	if err != nil {
		return PlainOutput{}, err
	}
	proof, err := v2crypto.ProveRange(commit, blind[:], value)
	if err != nil {
		return PlainOutput{}, err
	}
	return PlainOutput{
		Output: types.Output{
			Features:   types.OutputFeaturesPlain,
			Commit:     commit,
			RangeProof: proof,
		},
		Blinding: blind,
		Value:    value,
	}, nil
}

// BuildLegacyClaim builds a transaction that spends a single legacy
// balance UTXO (carried from v1 sumary.psk) into a fresh native MW
// output owned by the wallet.
//
// The chain validator checks the input signature against the original
// v1 secp256k1 public key derived from `legacyAddress`. The resulting
// Plain output is owned by the wallet via the returned blinding
// factor.
func (w *Wallet) BuildLegacyClaim(
	legacyAddress string,
	balance int64,
	legacyCommit types.Commitment,
	currentHeight uint64,
) (*types.Transaction, PlainOutput, error) {
	entry, ok := w.Legacy[legacyAddress]
	if !ok {
		return nil, PlainOutput{}, fmt.Errorf("wallet: no legacy key for %s", legacyAddress)
	}
	// 1. Build the legacy input with an ECDSA signature over the
	//    canonical claim message.
	msg := types.LegacySpendMessage(legacyAddress, legacyCommit, currentHeight)
	sig, err := signLegacyMessage([]byte(entry.PrivateKey), msg)
	if err != nil {
		return nil, PlainOutput{}, fmt.Errorf("wallet: sign claim: %w", err)
	}
	in := types.Input{
		Features:     types.OutputFeaturesLegacy,
		Commit:       legacyCommit,
		LegacySig:    sig,
		LegacyAddr:   legacyAddress,
		LegacyAmount: balance,
	}

	// 2. Build a fresh Plain output that the wallet's Ed25519 master
	//    owns via the recorded blinding factor.
	out, err := NewPlainOutput(balance)
	if err != nil {
		return nil, PlainOutput{}, err
	}

	// 3. Kernel: excess = (output blind − input "blind"). The legacy
	//    input has a publicly-known blinding factor derived from the
	//    address (genesis bundler used SHA-256("NosoX legacy blind " +
	//    addr)). The kernel-excess scalar is therefore
	//      x_excess = blind_out − legacy_blind
	//    and the kernel commitment is x_excess · G.
	legacyBlind := sha256.Sum256([]byte("NosoX legacy blind " + legacyAddress))
	excessScalar := scalarSub(out.Blinding[:], legacyBlind[:])
	excessCommit, err := v2crypto.PedersenCommit(0, excessScalar[:])
	if err != nil {
		return nil, PlainOutput{}, err
	}
	kernel := types.Kernel{
		Features:   types.KernelFeaturesLegacyClaim,
		Fee:        0,
		LockHeight: 0,
		Excess:     excessCommit,
	}
	kernelHash := types.KernelID(&kernel)
	excessSig, err := v2crypto.SchnorrSign(excessScalar[:], kernelHash[:])
	if err != nil {
		return nil, PlainOutput{}, err
	}
	kernel.ExcessSig = excessSig

	return &types.Transaction{
		Inputs:  []types.Input{in},
		Outputs: []types.Output{out.Output},
		Kernels: []types.Kernel{kernel},
	}, out, nil
}

// BuildGVTRedeem spends a single inherited GVT (slot N) for
// GVTBaseValue NOSO base units (70 NOSO). The owner signs with their
// original v1 secp256k1 key, just like a balance claim.
func (w *Wallet) BuildGVTRedeem(
	gvtSlot uint8,
	legacyAddress string,
	gvtCommit types.Commitment,
	currentHeight uint64,
) (*types.Transaction, PlainOutput, error) {
	entry, ok := w.Legacy[legacyAddress]
	if !ok {
		return nil, PlainOutput{}, fmt.Errorf("wallet: no legacy key for GVT owner %s", legacyAddress)
	}
	msg := types.LegacySpendMessage(legacyAddress, gvtCommit, currentHeight)
	sig, err := signLegacyMessage([]byte(entry.PrivateKey), msg)
	if err != nil {
		return nil, PlainOutput{}, err
	}
	in := types.Input{
		Features:     types.OutputFeaturesLegacyGVT,
		Commit:       gvtCommit,
		LegacySig:    sig,
		LegacyAddr:   legacyAddress,
		LegacyAmount: types.GVTBaseValue,
	}
	out, err := NewPlainOutput(types.GVTBaseValue)
	if err != nil {
		return nil, PlainOutput{}, err
	}
	// Same blinding derivation as the genesis bundler.
	gvtBlind := sha256.Sum256([]byte(fmt.Sprintf("NosoX legacy GVT blind %02d %s", gvtSlot, legacyAddress)))
	excessScalar := scalarSub(out.Blinding[:], gvtBlind[:])
	excessCommit, err := v2crypto.PedersenCommit(0, excessScalar[:])
	if err != nil {
		return nil, PlainOutput{}, err
	}
	kernel := types.Kernel{
		Features:   types.KernelFeaturesLegacyClaim,
		Fee:        0,
		LockHeight: 0,
		Excess:     excessCommit,
	}
	kernelHash := types.KernelID(&kernel)
	excessSig, err := v2crypto.SchnorrSign(excessScalar[:], kernelHash[:])
	if err != nil {
		return nil, PlainOutput{}, err
	}
	kernel.ExcessSig = excessSig
	return &types.Transaction{
		Inputs:  []types.Input{in},
		Outputs: []types.Output{out.Output},
		Kernels: []types.Kernel{kernel},
	}, out, nil
}

// BuildGVTTransfer transfers GVT slot N from the owner (v1 holder) to
// `newOwner` (a NosoX Ed25519 address — here represented as a 32-byte
// blinding factor since GVTs in NosoX are tied to the blinding factor,
// not an address). The receiver discovers the GVT by scanning UTXOs
// for outputs with their commit pattern.
//
// Identity (slot number) is preserved: the new output is also a
// LegacyGVT with the same GVTNumber.
func (w *Wallet) BuildGVTTransfer(
	gvtSlot uint8,
	legacyAddress string,
	gvtCommit types.Commitment,
	receiverBlinding [32]byte,
	currentHeight uint64,
) (*types.Transaction, error) {
	entry, ok := w.Legacy[legacyAddress]
	if !ok {
		return nil, fmt.Errorf("wallet: no legacy key for GVT owner %s", legacyAddress)
	}
	msg := types.LegacySpendMessage(legacyAddress, gvtCommit, currentHeight)
	sig, err := signLegacyMessage([]byte(entry.PrivateKey), msg)
	if err != nil {
		return nil, err
	}
	in := types.Input{
		Features:     types.OutputFeaturesLegacyGVT,
		Commit:       gvtCommit,
		LegacySig:    sig,
		LegacyAddr:   legacyAddress,
		LegacyAmount: types.GVTBaseValue,
	}
	// New GVT output owned by receiverBlinding.
	commit, err := v2crypto.PedersenCommit(types.GVTBaseValue, receiverBlinding[:])
	if err != nil {
		return nil, err
	}
	newOut := types.Output{
		Features:      types.OutputFeaturesLegacyGVT,
		Commit:        commit,
		LegacyAddress: legacyAddress, // historical record of the v1 owner
		LegacyAmount:  types.GVTBaseValue,
		GVTNumber:     gvtSlot,
	}
	// Excess = receiverBlinding − v1GVTBlinding
	v1Blind := sha256.Sum256([]byte(fmt.Sprintf("NosoX legacy GVT blind %02d %s", gvtSlot, legacyAddress)))
	excessScalar := scalarSub(receiverBlinding[:], v1Blind[:])
	excessCommit, err := v2crypto.PedersenCommit(0, excessScalar[:])
	if err != nil {
		return nil, err
	}
	kernel := types.Kernel{
		Features:   types.KernelFeaturesLegacyClaim,
		Fee:        0,
		LockHeight: 0,
		Excess:     excessCommit,
	}
	kHash := types.KernelID(&kernel)
	kSig, err := v2crypto.SchnorrSign(excessScalar[:], kHash[:])
	if err != nil {
		return nil, err
	}
	kernel.ExcessSig = kSig
	return &types.Transaction{
		Inputs:  []types.Input{in},
		Outputs: []types.Output{newOut},
		Kernels: []types.Kernel{kernel},
	}, nil
}

// signLegacyMessage wraps v1 ECDSA-SHA1 signing so the builder can
// produce legacy-spend signatures the chain validator accepts.
func signLegacyMessage(privKeyB64, msg []byte) (string, error) {
	// Defer to internal v1 crypto.
	return v1cryptoSignWrapper(string(privKeyB64), msg)
}

// scalarSub returns (a − b) mod n on secp256k1 as a 32-byte scalar.
// Constant-time via ModNScalar arithmetic.
func scalarSub(a, b []byte) [32]byte {
	var as, bs secp.ModNScalar
	var ab, bb [32]byte
	copy(ab[:], a)
	copy(bb[:], b)
	as.SetBytes(&ab)
	bs.SetBytes(&bb)
	bs.Negate()
	as.Add(&bs)
	return as.Bytes()
}

// Compile-time sanity check — kept because big.Int is used elsewhere.
var _ = big.NewInt
