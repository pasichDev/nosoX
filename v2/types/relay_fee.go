package types

import (
	"math"
	"math/bits"
)

// DefaultRelayFeeRate is the production relay floor: base units of fee per
// 1000 bytes of a transaction's accounted size (see EstimateTxSize). It is a
// local relay policy, not consensus; the mempool's DefaultPolicy and the
// wallet's default fee both derive from it.
const DefaultRelayFeeRate = 1000

// EstimateTxSize is the accounted size, the one relay fees are charged on, of
// a transaction with the given shape and per-element proof and signature
// sizes. mempool.transactionSize computes the same value from a real
// transaction; a test pins the two together.
func EstimateTxSize(inputs, outputs, kernels, proofBytes, sigBytes int) int {
	return 128*(inputs+outputs+kernels) + 64*inputs + outputs*proofBytes + kernels*sigBytes
}

// MinRelayFee is the smallest fee that clears a relay rate for a transaction
// of the given accounted size: ceil(rate*size/1000).
func MinRelayFee(rate uint64, size int) uint64 {
	hi, lo := bits.Mul64(rate, uint64(size))
	lo, carry := bits.Add64(lo, 999, 0)
	hi += carry
	if hi >= 1000 {
		return math.MaxUint64
	}
	q, _ := bits.Div64(hi, lo, 1000)
	return q
}
