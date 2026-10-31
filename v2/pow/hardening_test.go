package pow

import (
	"github.com/pasichDev/noso-go/v2/types"
	"math"
	"testing"
)

func TestLWMAMaxDifficultySteady(t *testing.T) {
	st := make([]int64, 90)
	ds := make([]uint64, 90)
	for i := range st {
		st[i] = 120
		ds[i] = math.MaxUint64
	}
	if got := LWMA3(st, ds, 120); got != math.MaxUint64 {
		t.Fatalf("overflow: steady maximum became %d", got)
	}
}
func TestVerifyZeroDifficulty(t *testing.T) {
	if Verify(&types.BlockHeader{}) {
		t.Fatal("zero difficulty accepted")
	}
}
func TestLWMASaturates(t *testing.T) {
	if got := LWMA3([]int64{1}, []uint64{math.MaxUint64}, 120); got != math.MaxUint64 {
		t.Fatalf("must saturate instead of wrapping: %d", got)
	}
}
