// builder.go implements the output-construction helpers used by the
// CLI's `wallet pay`, `wallet receive` and `wallet finalize` flows.
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
// (slatepack.go) and the cryptographic primitives in v2/crypto.

package wallet

import (
	"crypto/rand"
	"errors"

	v2crypto "github.com/pasichDev/nosoX/v2/crypto"
	"github.com/pasichDev/nosoX/v2/types"
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
