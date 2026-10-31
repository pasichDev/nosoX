package pow

import (
	"github.com/pasichDev/noso-go/v2/types"
	"math/big"
)

// LWMA3 evaluates the repository's weighted-window formula exactly. The name
// is historical; equivalence to a published LWMA-3 variant is not established.
// Arithmetic saturates at uint64 rather than wrapping consensus difficulty.
func LWMA3(solveTimes []int64, difficulties []uint64, target int64) uint64 {
	n := len(solveTimes)
	if n == 0 || len(difficulties) != n || target <= 0 {
		return types.MinDifficulty
	}
	sumD, sumWT := new(big.Int), new(big.Int)
	maxST := new(big.Int).Mul(big.NewInt(target), big.NewInt(6))
	for i, st := range solveTimes {
		if st < 1 {
			st = 1
		}
		t := big.NewInt(st)
		if t.Cmp(maxST) > 0 {
			t.Set(maxST)
		}
		t.Mul(t, new(big.Int).SetUint64(uint64(i)+1))
		sumWT.Add(sumWT, t)
		sumD.Add(sumD, new(big.Int).SetUint64(difficulties[i]))
	}
	numerator := new(big.Int).Mul(sumD, big.NewInt(target))
	numerator.Mul(numerator, new(big.Int).SetUint64(uint64(n)+1))
	denominator := new(big.Int).Lsh(sumWT, 1)
	d := numerator.Quo(numerator, denominator)
	if d.Sign() <= 0 {
		return types.MinDifficulty
	}
	if !d.IsUint64() {
		return ^uint64(0)
	}
	return d.Uint64()
}
