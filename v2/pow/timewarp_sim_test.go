package pow

import (
	"math"
	"math/rand"
	"sort"
	"testing"

	"github.com/pasichDev/nosoX/v2/types"
)

// simulateChain mines blocks with the real LWMA3 and an exponential solve
// process at constant total hashrate. A fraction p of blocks come from an
// attacker following strategy; honest miners stamp now (raised to the lowest
// timestamp the consensus rule allows). It returns the mean real interval.
//
// rule "mtp": a timestamp must exceed the median of the last
// MedianTimeSpan blocks and may be at most `ftl` ahead of the clock.
// rule "monotonic": a timestamp must exceed the tip's.
func simulateChain(rule, strategy string, p float64, ftl int64, blocks int, seed int64) (avgGap, worstGap float64) {
	const n = types.DifficultyWindow
	target := types.TargetBlockTimeSeconds
	hashrate := 1000.0 / float64(target) // difficulty 1000 gives the target interval
	r := rand.New(rand.NewSource(seed))
	stamps := make([]int64, 0, blocks+n)
	solve := make([]int64, 0, blocks+n)
	diffs := make([]uint64, 0, blocks+n)
	for i := 0; i < n+types.MedianTimeSpan; i++ {
		stamps = append(stamps, int64(i)*target)
		solve = append(solve, target)
		diffs = append(diffs, 1000)
	}
	now := float64(stamps[len(stamps)-1])
	warm := blocks / 5
	start, counted := 0.0, 0
	for i := 0; i < blocks; i++ {
		d := LWMA3(solve[len(solve)-n:], diffs[len(diffs)-n:], target)
		gap := -math.Log(1-r.Float64()) * float64(d) / hashrate
		now += gap
		if i == warm {
			start, counted = now, 0
		}
		counted++
		worstGap = math.Max(worstGap, gap)
		var floor int64
		if rule == "mtp" {
			w := append([]int64(nil), stamps[len(stamps)-types.MedianTimeSpan:]...)
			sort.Slice(w, func(a, b int) bool { return w[a] < w[b] })
			floor = w[len(w)/2] + 1
		} else {
			floor = stamps[len(stamps)-1] + 1
		}
		ts := int64(now)
		if r.Float64() < p {
			switch strategy {
			case "future":
				ts = int64(now) + ftl
			case "past":
				ts = floor
			}
		}
		if ts < floor {
			ts = floor
		}
		solve = append(solve, ts-stamps[len(stamps)-1])
		stamps = append(stamps, ts)
		diffs = append(diffs, d)
	}
	return (now - start) / float64(counted), worstGap
}

func meanInterval(rule, strategy string, p float64, ftl int64) float64 {
	var sum float64
	const seeds = 3
	for s := int64(1); s <= seeds; s++ {
		a, _ := simulateChain(rule, strategy, p, ftl, 40000, s)
		sum += a / seeds
	}
	return sum
}

// TestTimeWarpFutureLimit shows with the real LWMA3 that the old two-hour
// future limit lets a small miner slow the chain, and that the adopted limit
// keeps the mean interval within 5% of
// target for every attacker share (the 3% worst case
// at 540 s grows to 8% at 720 s and 17% at 900 s, see TestFutureLimitSweep).
func TestTimeWarpFutureLimit(t *testing.T) {
	target := float64(types.TargetBlockTimeSeconds)
	shares := []float64{0.01, 0.05, 0.10, 0.15, 0.20, 0.33, 0.50}

	// Documented defect: two hours, tip-monotonic rule only.
	worst := 0.0
	for _, p := range shares {
		worst = math.Max(worst, meanInterval("monotonic", "future", p, 7200))
	}
	if worst < 1.5*target {
		t.Fatalf("expected the legacy 7200 s rule to slow blocks by at least 1.5x, worst mean %.0f s", worst)
	}
	t.Logf("legacy rule (7200 s, monotonic): worst mean interval %.0f s (target %.0f s)", worst, target)

	// Replacing the monotonic rule by median-time-past makes things worse:
	// out-of-order stamps give negative solve times, which LWMA3 floors at 1 s,
	// so the attacker speeds the chain up instead. Pin that finding so nobody
	// swaps the rule without re-running the numbers.
	mtpOnly := 0.0
	for _, p := range shares {
		mtpOnly = math.Max(mtpOnly, math.Abs(meanInterval("mtp", "future", p, types.MaxFutureDriftSeconds)/target-1))
	}
	if mtpOnly < 0.2 {
		t.Fatalf("expected a median-time-past-only rule to distort the interval by >20%%, got %.1f%%", mtpOnly*100)
	}
	t.Logf("median-time-past only, ftl=%d: worst deviation %.0f%%", types.MaxFutureDriftSeconds, mtpOnly*100)

	// Adopted rule: strictly increasing timestamps plus the short future limit.
	// The future-stamping attack must stay within 5% of target. This bound is
	// what pins the limit: the same simulation gives 8% at 720 s and 17% at 900 s
	// (TestFutureLimitSweep), so a looser limit fails here.
	ftl := types.MaxFutureDriftSeconds
	for _, p := range shares {
		got := meanInterval("monotonic", "future", p, ftl)
		t.Logf("monotonic, ftl=%d, future, p=%.2f: mean %.1f s", ftl, p, got)
		if got < 0.95*target || got > 1.05*target {
			t.Errorf("future-stamping share %.2f: mean interval %.1f s outside +-5%% of %.0f s", p, got, target)
		}
	}
	// Stamping the lowest legal timestamp ("past") is a property of the
	// strictly-increasing rule and does not depend on the future limit: at 50%
	// hashrate it lengthens blocks by about 8%. Bound it separately.
	for _, p := range shares {
		got := meanInterval("monotonic", "past", p, ftl)
		t.Logf("monotonic, past, p=%.2f: mean %.1f s", p, got)
		if got < 0.90*target || got > 1.10*target {
			t.Errorf("past-stamping share %.2f: mean interval %.1f s outside +-10%% of %.0f s", p, got, target)
		}
	}
}

// TestFutureLimitSweep documents how the bound was chosen. Run with -v.
func TestFutureLimitSweep(t *testing.T) {
	if testing.Short() {
		t.Skip("sweep")
	}
	for _, ftl := range []int64{120, 240, 360, 540, 720, 900, 1800, 3600} {
		worst := 0.0
		for _, p := range []float64{0.05, 0.10, 0.20, 0.33} {
			worst = math.Max(worst, math.Abs(meanInterval("monotonic", "future", p, ftl)/float64(types.TargetBlockTimeSeconds)-1))
		}
		t.Logf("ftl=%4d s: worst deviation from target %.1f%%", ftl, worst*100)
	}
}
