package pow

import (
	"math/big"
	"testing"

	"github.com/pasichDev/nosoX/v2/types"
)

func TestNosoXHashIsDeterministic(t *testing.T) {
	hdr := types.BlockHeader{Height: 1, Difficulty: 1}
	a := Hash(&hdr)
	b := Hash(&hdr)
	if a != b {
		t.Fatalf("Hash is non-deterministic: %x vs %x", a, b)
	}
}

func TestNosoXMineEasyDifficulty(t *testing.T) {
	// At Difficulty=1 the target equals MaxTarget, so ANY hash is valid.
	hdr := types.BlockHeader{Height: 1, Difficulty: 1, Nonce: 0}
	if !Verify(&hdr) {
		t.Fatal("Verify failed at Difficulty=1")
	}
}

func TestNosoXMineRequiresSearch(t *testing.T) {
	// At Difficulty=256, the target is MaxTarget/256, so ~1 in 256 hashes
	// is valid. Mine for at most a few hundred nonces to find one.
	hdr := types.BlockHeader{Height: 1, Difficulty: 256, Nonce: 0}
	found := false
	for i := uint64(0); i < 2048; i++ {
		hdr.Nonce = i
		if Verify(&hdr) {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("did not find a valid nonce in 2048 tries at Difficulty=256")
	}
}

func TestTargetMath(t *testing.T) {
	if Target(1).Cmp(MaxTarget) != 0 {
		t.Errorf("Target(1) != MaxTarget")
	}
	half := new(big.Int).Rsh(MaxTarget, 1)
	if Target(2).Cmp(half) != 0 {
		t.Errorf("Target(2) != MaxTarget/2")
	}
}

func TestLWMA3KeepsSteady(t *testing.T) {
	// If every block solved exactly at target time with the same
	// difficulty, LWMA-3 should re-emit (approximately) the same value.
	const D = 1000
	st := make([]int64, types.DifficultyWindow)
	diffs := make([]uint64, types.DifficultyWindow)
	for i := range st {
		st[i] = types.TargetBlockTimeSeconds
		diffs[i] = D
	}
	got := LWMA3(st, diffs, types.TargetBlockTimeSeconds)
	if got < D*9/10 || got > D*11/10 {
		t.Errorf("LWMA3 steady-state difficulty = %d, want ~%d", got, D)
	}
}

func TestLWMA3RespondsToSpeedup(t *testing.T) {
	// If blocks solve at half the target time, difficulty should rise.
	const D = 1000
	st := make([]int64, types.DifficultyWindow)
	diffs := make([]uint64, types.DifficultyWindow)
	for i := range st {
		st[i] = types.TargetBlockTimeSeconds / 2
		diffs[i] = D
	}
	got := LWMA3(st, diffs, types.TargetBlockTimeSeconds)
	if got <= D {
		t.Errorf("LWMA3 did not raise difficulty (got %d)", got)
	}
}
