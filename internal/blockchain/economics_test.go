package blockchain

import "testing"

func TestBlockRewardHalving(t *testing.T) {
	cases := []struct {
		block int64
		want  int64
	}{
		{0, PremineAmount},
		{1, 5_000_000_000},
		{209_999, 5_000_000_000},
		{210_000, 2_500_000_000},
		{419_999, 2_500_000_000},
		{420_000, 1_250_000_000},
		{2_099_999, InitialReward >> 9}, // 9_765_625
		{2_100_000, InitialReward >> 10},
		{2_310_000, 0}, // beyond HalvingSteps -> zero
	}
	for _, c := range cases {
		got := BlockReward(c.block)
		if got != c.want {
			t.Errorf("BlockReward(%d) = %d, want %d", c.block, got, c.want)
		}
	}
}

func TestMinimumTransferFee(t *testing.T) {
	cases := []struct {
		amount, fee int64
	}{
		{0, MinimumFee},
		{1, MinimumFee},
		{10_000_000_000, 1_000_000}, // amount / 10000 = 1_000_000 = MinimumFee
		{20_000_000_000, 2_000_000}, // 2x
	}
	for _, c := range cases {
		got := MinimumTransferFee(c.amount)
		if got != c.fee {
			t.Errorf("MinimumTransferFee(%d) = %d, want %d", c.amount, got, c.fee)
		}
	}
}

func TestCustomizationFeeTransition(t *testing.T) {
	if got := CustomizationFeeFor(0); got != CustomizationFeeEarly {
		t.Errorf("block 0 fee = %d", got)
	}
	if got := CustomizationFeeFor(UpdateCustomizationFeeBlock - 1); got != CustomizationFeeEarly {
		t.Errorf("just-before-update fee = %d", got)
	}
	if got := CustomizationFeeFor(UpdateCustomizationFeeBlock); got != CustomizationFeeLate {
		t.Errorf("update-block fee = %d", got)
	}
}

func TestGetSupplyMatchesFixtureSnapshot(t *testing.T) {
	// At the snapshot block 59238, the sumary.psk fixture sums to
	// 297_180_390_730_000 base units. Our GetSupply formula should yield
	// at most that value (it's the *expected* maximum supply if all rewards
	// are accounted for; actual snapshot may be a few NOSO short due to
	// unflushed PoS/MN credits at snapshot time).
	expected := GetSupply(59238)
	t.Logf("GetSupply(59238) = %d (%.4f NOSO)", expected, float64(expected)/1e8)
	if expected < 297_180_390_730_000 {
		t.Errorf("supply under-estimate: %d < snapshot total", expected)
	}
	// And it should be only modestly above (premine + 59238 * 50 NOSO ≈
	// 2_972_203.9073 NOSO, i.e. 297_220_390_730_000 base units).
	if expected > 298_000_000_000_000 {
		t.Errorf("supply over-estimate: %d", expected)
	}
}
