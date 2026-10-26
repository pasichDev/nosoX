package types

// Version-4 native-block resource envelope. Four outputs allow an ordinary
// payment and change plus scheduled coinbase and transparent fee destination.
// These limits are consensus rules, not per-node policies; every legal suffix
// of MaxReorgBlocks fits the derived aggregate envelope. Trusted genesis has
// its separately validated legacy-allocation envelope. No economics change.
const (
	MaxBlockInputs     = 4
	MaxBlockOutputs    = 4
	MaxBlockKernels    = 4
	MaxBlockBodyBytes  = 64 << 10
	MaxRangeProofBytes = 1 + 64*(33+33+33+32+32+32+32)
	MaxReorgBlocks     = 1024
	MaxReorgBodyBytes  = MaxReorgBlocks * MaxBlockBodyBytes
)
