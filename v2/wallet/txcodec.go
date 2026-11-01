package wallet

import (
	"encoding/binary"
	"errors"
	"fmt"

	v2crypto "github.com/pasichDev/nosoX/v2/crypto"
	"github.com/pasichDev/nosoX/v2/types"
)

// Canonical binary transaction codec used by slates, the wallet state file and
// the submittransaction RPC. Decoding is strict: every count is bounded before
// allocation, every point is validated, unknown feature bytes are rejected and
// trailing bytes are an error.
//
//	tx     = ver(1) nIn(1) input* nOut(1) output* nKern(1) kernel*
//	input  = features(1) commit(33)
//	output = features(1) commit(33) proofLen(2) proof
//	kernel = features(1) fee(8) lock(8) excess(33) sigLen(1) sig
//
// All integers are big-endian.

const (
	txCodecVersion = 1
	// MaxEncodedTxBytes bounds any encoded transaction (consensus caps a block
	// body at types.MaxBlockBodyBytes; the encoding adds only small headers).
	MaxEncodedTxBytes = types.MaxBlockBodyBytes + 4096
	kernelSigLen      = 65
)

// ErrCodec is wrapped by every decoding failure.
var ErrCodec = errors.New("wallet: malformed encoding")

func codecErr(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrCodec, fmt.Sprintf(format, a...))
}

type reader struct {
	b   []byte
	err error
}

func (r *reader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || n > len(r.b) {
		r.err = codecErr("truncated")
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}
func (r *reader) u8() uint8 {
	b := r.take(1)
	if b == nil {
		return 0
	}
	return b[0]
}
func (r *reader) u16() uint16 {
	b := r.take(2)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}
func (r *reader) u32() uint32 {
	b := r.take(4)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}
func (r *reader) u64() uint64 {
	b := r.take(8)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}
func (r *reader) point() [33]byte {
	var p [33]byte
	b := r.take(33)
	if b == nil {
		return p
	}
	copy(p[:], b)
	if !v2crypto.ValidPublicPoint(p) {
		r.err = codecErr("invalid curve point")
	}
	return p
}

func validOutputFeatures(f types.OutputFeatures) bool {
	return f == types.OutputFeaturesPlain || f == types.OutputFeaturesCoinbase
}

func appendInput(dst []byte, in types.Input) []byte {
	dst = append(dst, byte(in.Features))
	return append(dst, in.Commit[:]...)
}

func appendOutput(dst []byte, o types.Output) ([]byte, error) {
	if len(o.RangeProof) > types.MaxRangeProofBytes {
		return nil, codecErr("range proof too large")
	}
	dst = append(dst, byte(o.Features))
	dst = append(dst, o.Commit[:]...)
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(o.RangeProof)))
	return append(dst, o.RangeProof...), nil
}

func (r *reader) input() types.Input {
	f := types.OutputFeatures(r.u8())
	c := r.point()
	if r.err == nil && !validOutputFeatures(f) {
		r.err = codecErr("unknown input features")
	}
	return types.Input{Features: f, Commit: c}
}

func (r *reader) output() types.Output {
	f := types.OutputFeatures(r.u8())
	c := r.point()
	n := int(r.u16())
	if r.err == nil && (!validOutputFeatures(f) || n > types.MaxRangeProofBytes) {
		r.err = codecErr("bad output header")
		return types.Output{}
	}
	p := r.take(n)
	if r.err != nil {
		return types.Output{}
	}
	return types.Output{Features: f, Commit: c, RangeProof: append([]byte(nil), p...)}
}

// EncodeTx serializes tx canonically.
func EncodeTx(tx *types.Transaction) ([]byte, error) {
	if tx == nil || len(tx.Inputs) > types.MaxBlockInputs || len(tx.Outputs) > types.MaxBlockOutputs || len(tx.Kernels) > types.MaxBlockKernels {
		return nil, codecErr("transaction bounds")
	}
	b := []byte{txCodecVersion, byte(len(tx.Inputs))}
	for _, in := range tx.Inputs {
		b = appendInput(b, in)
	}
	b = append(b, byte(len(tx.Outputs)))
	for _, o := range tx.Outputs {
		var err error
		if b, err = appendOutput(b, o); err != nil {
			return nil, err
		}
	}
	b = append(b, byte(len(tx.Kernels)))
	for _, k := range tx.Kernels {
		if len(k.ExcessSig) != kernelSigLen {
			return nil, codecErr("kernel signature must be %d bytes", kernelSigLen)
		}
		b = append(b, byte(k.Features))
		b = binary.BigEndian.AppendUint64(b, k.Fee)
		b = binary.BigEndian.AppendUint64(b, k.LockHeight)
		b = append(b, k.Excess[:]...)
		b = append(b, byte(len(k.ExcessSig)))
		b = append(b, k.ExcessSig...)
	}
	if len(b) > MaxEncodedTxBytes {
		return nil, codecErr("transaction too large")
	}
	return b, nil
}

// DecodeTx parses a transaction produced by EncodeTx.
func DecodeTx(raw []byte) (*types.Transaction, error) {
	if len(raw) == 0 || len(raw) > MaxEncodedTxBytes {
		return nil, codecErr("size")
	}
	r := &reader{b: raw}
	if v := r.u8(); r.err == nil && v != txCodecVersion {
		return nil, codecErr("unsupported transaction encoding version %d", v)
	}
	tx := &types.Transaction{}
	nIn := int(r.u8())
	if r.err == nil && nIn > types.MaxBlockInputs {
		return nil, codecErr("too many inputs")
	}
	for i := 0; i < nIn && r.err == nil; i++ {
		tx.Inputs = append(tx.Inputs, r.input())
	}
	nOut := int(r.u8())
	if r.err == nil && nOut > types.MaxBlockOutputs {
		return nil, codecErr("too many outputs")
	}
	for i := 0; i < nOut && r.err == nil; i++ {
		tx.Outputs = append(tx.Outputs, r.output())
	}
	nK := int(r.u8())
	if r.err == nil && nK > types.MaxBlockKernels {
		return nil, codecErr("too many kernels")
	}
	for i := 0; i < nK && r.err == nil; i++ {
		var k types.Kernel
		k.Features = types.KernelFeatures(r.u8())
		k.Fee = r.u64()
		k.LockHeight = r.u64()
		k.Excess = r.point()
		sl := int(r.u8())
		if r.err == nil && (sl != kernelSigLen || (k.Features != types.KernelFeaturesPlain && k.Features != types.KernelFeaturesCoinbase)) {
			r.err = codecErr("bad kernel header")
		}
		sig := r.take(sl)
		if r.err == nil {
			k.ExcessSig = append([]byte(nil), sig...)
			tx.Kernels = append(tx.Kernels, k)
		}
	}
	if r.err != nil {
		return nil, r.err
	}
	if len(r.b) != 0 {
		return nil, codecErr("trailing bytes")
	}
	return tx, nil
}
