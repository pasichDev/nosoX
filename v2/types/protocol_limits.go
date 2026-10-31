package types

// Native-block resource envelope. Four outputs allow an ordinary payment and
// change plus the block's one coinbase output, which carries the subsidy and
// all fees (there is no separate fee output). These limits are consensus rules, not per-node policies; every legal suffix
// of MaxReorgBlocks fits the derived aggregate envelope. Genesis is empty and
// must carry no inputs, outputs or kernels.
const (
	MaxBlockInputs  = 4
	MaxBlockOutputs = 4
	MaxBlockKernels = 4
	// MaxBlockBodyBytes is a consensus ceiling, not an operative limit: the item
	// limits above already cap the charged body at 60,168 bytes (4 inputs,
	// 4 outputs with maximum-size range proofs, 4 kernels; see
	// TestMaximalBodyStaysUnderByteLimit), so the byte checks never reject a
	// block that passed the item limits. It stays because MaxReorgBodyBytes
	// derives from it and changing it would change consensus.
	MaxBlockBodyBytes  = 64 << 10
	MaxRangeProofBytes = 1 + 64*(33+33+33+32+32+32+32)
	MaxReorgBlocks     = 1024
	MaxReorgBodyBytes  = MaxReorgBlocks * MaxBlockBodyBytes
)
