// Package blockchain implements the economic and validation rules of the
// Noso blockchain — reward halving, supply, fees, and per-block validation.
//
// All constants are taken verbatim from `mpcoin.pas`, `nosogeneral.pas`,
// `masterpaskalform.pas`, and `mpblock.pas`. Do NOT tweak these values
// without a corresponding hard fork; they are baked into the historical
// chain and changing them produces a different chain.
package blockchain

// Economic constants. Comments cite the Pascal source.
const (
	// PremineAmount is the genesis (block 0) balance assigned to
	// `GenesisAddress`. Source: `masterpaskalform.pas`.
	PremineAmount int64 = 1_030_390_730_000

	// InitialReward is the per-block reward for blocks 1..BlockHalvingInterval-1.
	// Equivalent to 50 NOSO with 8 decimals.
	InitialReward int64 = 5_000_000_000

	// BlockHalvingInterval is the number of blocks between halvings.
	BlockHalvingInterval int64 = 210_000

	// HalvingSteps is the maximum number of halvings before the reward
	// drops to zero permanently.
	HalvingSteps int64 = 10

	// Comisiontrfr (sic — Pascal misspelling preserved) is the divisor for
	// the per-transfer fee: fee = amount / Comisiontrfr.
	Comisiontrfr int64 = 10_000

	// MinimumFee is the floor below which fees never drop, in base units.
	MinimumFee int64 = 1_000_000

	// CustomizationFee is the fee charged for the CUSTOM order type
	// (registering an alias). For blocks <= UpdateCustomizationFeeBlock,
	// the fee is this value (25_000); afterwards it's `MinimumFee`.
	CustomizationFeeEarly int64 = 25_000
	CustomizationFeeLate  int64 = 1_000_000

	// UpdateCustomizationFeeBlock — block at which CustomizationFee
	// transitioned from CustomizationFeeEarly to CustomizationFeeLate.
	// Source: `mpprotocol.pas:744-770`.
	UpdateCustomizationFeeBlock int64 = 162_000

	// PoSBlockStart marks the first block at which Proof-of-Stake
	// rewards apply (`mpblock.pas:260` and analysis report).
	PoSBlockStart int64 = 8_424

	// PoSBlockEnd marks the last block at which PoS rewards apply; from
	// the following block, MNs take over the share.
	PoSBlockEnd int64 = 88_400

	// MNBlockStart is the first block at which masternodes earn rewards.
	MNBlockStart int64 = 48_010

	// DevFundStart is the first block at which the 10% dev fund cut applies.
	DevFundStart int64 = 88_400

	// PoSPercentageBP and MNsPercentageBP are basis points (out of 10_000).
	PoSPercentageBP int64 = 1_000 // 10%
	MNsPercentageBP int64 = 2_000 // 20% base
	DevPercentageBP int64 = 1_000 // 10%

	// PosStackCoins is the divisor for the PoS minimum stake check: a PoS
	// participant needs `GetSupply(block) * PosStackCoins / 10_000` units
	// of balance.
	PosStackCoins int64 = 20

	// SecurityBlocks is the reorg depth limit. Anything deeper is final.
	SecurityBlocks int64 = 100

	// SumMarkInterval is how often a sumary.psk snapshot is taken.
	SumMarkInterval int64 = 100

	// MNsLockExpireLapse is the number of blocks a masternode lock stays
	// in psos.dat before being pruned.
	MNsLockExpireLapse int64 = 2_016

	// MaxTransactionsPerBlock is the hard cap enforced by `BuildNewBlock`.
	MaxTransactionsPerBlock int = 2_000

	// BlockPeriodSeconds is the target block time.
	BlockPeriodSeconds int64 = 600

	// GenesysTimeStamp is the timestamp of block 0 (Unix seconds, UTC).
	GenesysTimeStamp int64 = 1_615_132_800

	// GenesysBlock0TimeStart is the special TimeStart of block 0.
	GenesysBlock0TimeStart int64 = 1_531_896_783

	// InitialBlockDiff is the difficulty set on the genesis block header.
	InitialBlockDiff int32 = 60
)

// Special addresses hardcoded in the Pascal codebase.
const (
	// GenesisAddress holds the premine. Source: `nosounit.pas`.
	GenesisAddress = "N4PeJyqj8diSXnfhxSQdLpo8ddXTaGd"

	// DevFundAddress is the destination of PROJCT-type payments and the
	// dev fund split. The string is a vanity label, not a derived address.
	DevFundAddress = "NpryectdevepmentfundsGE"
)

// BlockReward returns the base reward a miner earns for finalizing block
// `n`. Matches `GetBlockReward` in `mpblock.pas:489-500`:
//
//   - block 0          → PremineAmount (special-case, technically "reward")
//   - 0 < n < interval*(steps+1) → InitialReward / 2^(n / interval)
//   - otherwise         → 0
func BlockReward(n int64) int64 {
	if n == 0 {
		return PremineAmount
	}
	if n < 0 || n >= BlockHalvingInterval*(HalvingSteps+1) {
		return 0
	}
	halvings := n / BlockHalvingInterval
	return InitialReward >> halvings
}

// GetSupply returns the total expected circulating supply at the end of
// block `n`. This is an arithmetic series over reward eras.
//
// Pascal's `GetSupply` (`nosogeneral.pas:213-223`) only handles eras 0..1
// explicitly; we extend the logic to cover all halving eras for
// completeness. The result for blocks in eras 0..1 matches Pascal exactly.
func GetSupply(n int64) int64 {
	if n <= 0 {
		return PremineAmount
	}
	supply := PremineAmount
	remaining := n
	for era := int64(0); era <= HalvingSteps && remaining > 0; era++ {
		reward := InitialReward >> era
		if reward == 0 {
			break
		}
		// Each era has BlockHalvingInterval blocks; the first era starts
		// at block 1 (block 0 is the premine), so it covers blocks 1..interval.
		eraEnd := BlockHalvingInterval * (era + 1)
		if era == 0 {
			eraEnd = BlockHalvingInterval - 1 // blocks 1..interval-1 in Pascal logic
		}
		blocksInEra := eraEnd - era*BlockHalvingInterval + 1
		if era == 0 {
			blocksInEra = BlockHalvingInterval - 1
		}
		if blocksInEra > remaining {
			blocksInEra = remaining
		}
		supply += blocksInEra * reward
		remaining -= blocksInEra
	}
	return supply
}

// MinimumTransferFee returns the floor fee for transferring `amount` base
// units: `max(amount / Comisiontrfr, MinimumFee)`. Matches
// `GetMinimumFee` in `nosogeneral.pas:326-330`.
func MinimumTransferFee(amount int64) int64 {
	fee := amount / Comisiontrfr
	if fee < MinimumFee {
		return MinimumFee
	}
	return fee
}

// CustomizationFeeFor returns the fee charged for a CUSTOM order at the
// given block number.
func CustomizationFeeFor(block int64) int64 {
	if block < UpdateCustomizationFeeBlock {
		return CustomizationFeeEarly
	}
	return CustomizationFeeLate
}

// PoSEnabled reports whether PoS rewards are paid at this block.
func PoSEnabled(block int64) bool {
	return block >= PoSBlockStart && block < PoSBlockEnd
}

// MNsEnabled reports whether masternode rewards are paid at this block.
func MNsEnabled(block int64) bool { return block >= MNBlockStart }

// DevFundEnabled reports whether the 10% dev fund cut applies at this block.
func DevFundEnabled(block int64) bool { return block >= DevFundStart }

// PoSPercentage returns the PoS share in basis points at a given block.
// Outside the PoS window it returns 0. Inside, the analysis showed Pascal
// uses a tiered schedule; here we expose the constant cut (10%) used for
// the majority of the active window. Refine with the full table when the
// CLI exercises older blocks.
func PoSPercentage(block int64) int64 {
	if !PoSEnabled(block) {
		return 0
	}
	return PoSPercentageBP
}

// MNsPercentage returns the masternode share in basis points at a given
// block. Returns the base 20% for blocks in the active window. The Pascal
// code ramps this up after block 88_000; integrating that ramp is TBD.
func MNsPercentage(block int64) int64 {
	if !MNsEnabled(block) {
		return 0
	}
	return MNsPercentageBP
}

// DevPercentage returns the dev fund share in basis points at a given block.
func DevPercentage(block int64) int64 {
	if !DevFundEnabled(block) {
		return 0
	}
	return DevPercentageBP
}
