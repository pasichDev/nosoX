package pow

import "github.com/noso-project/noso-go/v2/types"

// LWMA3 implements Zawy's Linearly Weighted Moving Average difficulty
// adjustment, version 3. Inputs:
//
//   - solveTimes: the N most-recent inter-block deltas in seconds,
//     oldest first. N is typically 90 (DifficultyWindow).
//   - difficulties: the difficulty of each of those N blocks, oldest first.
//   - target: target block time in seconds (TargetBlockTimeSeconds).
//
// Output: difficulty for the next block.
//
// LWMA-3 punishes very short solve-times more than long ones to
// suppress timestamp manipulation. It is the standard choice for small,
// low-hashrate chains. Reference: zawy12/difficulty-algorithms.
func LWMA3(solveTimes []int64, difficulties []uint64, target int64) uint64 {
	N := int64(len(solveTimes))
	if N == 0 || int64(len(difficulties)) != N {
		return types.MinDifficulty
	}
	// LWMA-3:
	//   T = target_block_time
	//   for i in 1..N: solve_i clamped to [1, 6*T]
	//   sumD = sum(difficulty_i)
	//   sumWT = sum(i * solve_i)         // linear weights
	//   nextD = (sumD * T) / sumWT  (approx)
	var sumD, sumWT int64
	for i := int64(0); i < N; i++ {
		st := solveTimes[i]
		if st < 1 {
			st = 1
		}
		if st > 6*target {
			st = 6 * target
		}
		sumWT += (i + 1) * st
		sumD += int64(difficulties[i])
	}
	if sumWT == 0 {
		return types.MinDifficulty
	}
	// nextD scaled to keep arithmetic in int64 range.
	nextD := (sumD * target * (N + 1)) / (2 * sumWT)
	if nextD < int64(types.MinDifficulty) {
		nextD = int64(types.MinDifficulty)
	}
	return uint64(nextD)
}
