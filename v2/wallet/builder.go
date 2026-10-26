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
//   - Schnorr signatures use the project scalar-based path, which does not
//     establish constant-time execution.
//
// This file is the integration point between the Slatepack codec
// (slatepack.go), the legacy claim helpers (wallet.go), and the
// cryptographic primitives in v2/crypto.

package wallet

import (
	"crypto/rand"
	"errors"
	"math/big"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"

	v2crypto "github.com/pasichDev/noso-go/v2/crypto"
	"github.com/pasichDev/noso-go/v2/types"
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

// ErrLegacyContextRequired rejects the old height-based claim API, which cannot
// bind a trusted network/genesis or an exact destination leg. Use the v4 API.
var ErrLegacyContextRequired = errors.New("wallet: legacy claim requires explicit v4 network/genesis context")
var ErrGVTTransferUnsupported = errors.New("wallet: GVT identity transfer is unsupported; v4 only redeems trusted genesis allocations")

// BuildLegacyClaim is retained only to reject ambiguous pre-v4 callers.
func (w *Wallet) BuildLegacyClaim(legacyAddress string, balance int64, legacyCommit types.Commitment, currentHeight uint64) (*types.Transaction, PlainOutput, error) {
	return nil, PlainOutput{}, ErrLegacyContextRequired
}

// BuildGVTRedeem is retained only to reject ambiguous pre-v4 callers.
func (w *Wallet) BuildGVTRedeem(gvtSlot uint8, legacyAddress string, gvtCommit types.Commitment, currentHeight uint64) (*types.Transaction, PlainOutput, error) {
	return nil, PlainOutput{}, ErrLegacyContextRequired
}

// BuildGVTTransfer rejects identity creation outside explicitly trusted genesis.
func (w *Wallet) BuildGVTTransfer(gvtSlot uint8, legacyAddress string, gvtCommit types.Commitment, receiverBlinding [32]byte, currentHeight uint64) (*types.Transaction, error) {
	return nil, ErrGVTTransferUnsupported
}

// signLegacyMessage wraps v1 ECDSA-SHA1 signing so the builder can
// support historical tooling only; these signatures do not authorize v4 claims.
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
