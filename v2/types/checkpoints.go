package types

// Checkpoint pins a specific block hash at a specific height. Any block
// proposed at this height with a different hash is rejected by the
// validator, and any reorg attempting to cross this height is refused.
//
// Checkpoints exist to defend the early chain — when total hashrate is
// low — from rewrite attacks by a single well-funded miner.
//
// Trust model: the launcher publishes checkpoints periodically (e.g.
// every 1000 blocks for the first 50,000 blocks) by tagging release
// commits with new entries in MainnetCheckpoints. Operators who don't
// update their binary still benefit from earlier checkpoints. The
// security tradeoff is consensual: anyone running an older binary may
// accept a chain newer operators would reject.
//
// Checkpoints are NOT a substitute for hashrate — they only protect
// blocks PAST the checkpoint. The mainline chain is still
// proof-of-work-secured between checkpoints.
type Checkpoint struct {
	Height uint64
	Hash   Hash
}

// MainnetCheckpoints holds the launcher-published checkpoint sequence.
// Empty at v0.1 — the launcher tags release v0.2 with the first batch
// once mainnet has produced enough blocks to be checkpointed.
//
// Format reminder for whoever appends entries:
//   {Height: 1_000,  Hash: parseHex("…")},
//   {Height: 2_000,  Hash: parseHex("…")},
//
// To produce a hash use `nosox-cli tip` on a trusted node at the
// target height and copy its `hash` field.
var MainnetCheckpoints = []Checkpoint{
	// Reserved for the launch operator.
}

// TestnetCheckpoints is the testnet equivalent. Updated more freely
// than mainnet — testnet chain can be reset.
var TestnetCheckpoints []Checkpoint

// CheckpointForHeight returns (checkpoint, true) if a checkpoint
// exists at the given height. The list is expected to be small
// (~50–100 entries) so a linear scan is fine.
func CheckpointForHeight(list []Checkpoint, height uint64) (Checkpoint, bool) {
	for i := range list {
		if list[i].Height == height {
			return list[i], true
		}
	}
	return Checkpoint{}, false
}

// MaxCheckpointHeight returns the highest height in the list, or 0 if
// the list is empty. Used by reorg-depth logic to refuse rewrites
// across the most recent checkpoint.
func MaxCheckpointHeight(list []Checkpoint) uint64 {
	var maxH uint64
	for i := range list {
		if list[i].Height > maxH {
			maxH = list[i].Height
		}
	}
	return maxH
}
