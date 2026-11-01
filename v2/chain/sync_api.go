package chain

import (
	"math/big"
	"sync/atomic"

	"github.com/pasichDev/nosoX/v2/types"
)

// This file holds the read-only queries used by the network and RPC layers:
// unspent-output lookup with creation height, cumulative work, and block
// locators for finding a common ancestor with a peer.

// UTXOByCommit returns the unspent output for commit and the height of the
// block that created it. ok is false when the commitment is not unspent on the
// canonical chain.
func (c *Chain) UTXOByCommit(commit types.Commitment) (out types.Output, height uint64, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	o, found := c.store.UTXOByCommit(commit)
	if !found {
		return types.Output{}, 0, false
	}
	h, found := c.store.OutputHeight(commit)
	if !found {
		return types.Output{}, 0, false
	}
	return *o, h, true
}

// BlockWork returns the expected work of one block with the given declared
// difficulty (floor(2^256/(target+1))), the unit TotalWork accumulates.
func BlockWork(difficulty uint64) *big.Int { return blockWork(difficulty) }

// TotalWork returns the accumulated work of the canonical chain. The result is
// a fresh value the caller may modify. The sum is cached per tip and extended
// incrementally; a cold call walks the whole chain once.
func (c *Chain) TotalWork() *big.Int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return new(big.Int).Set(c.totalWorkLocked())
}

// totalWorkLocked requires c.mu. It never returns nil.
func (c *Chain) totalWorkLocked() *big.Int {
	tip, ok := c.store.Tip()
	if !ok {
		return new(big.Int)
	}
	tipID := types.HeaderID(&tip)
	if c.work.total != nil && c.work.tip == tipID {
		return c.work.total
	}
	// Extension or short reorg: walk back from the tip until the cached tip is
	// met. Otherwise (cold cache, deeper change) sum the whole chain once.
	var sum *big.Int
	if c.work.total != nil {
		acc := new(big.Int)
		for h, steps := tip.Height, 0; steps <= MaxReorgBlocks+2; h, steps = h-1, steps+1 {
			hdr := tip
			if h != tip.Height {
				b, err := c.store.BlockAt(h)
				if err != nil {
					break
				}
				hdr = b.Header
			}
			if h == c.work.height && types.HeaderID(&hdr) == c.work.tip {
				sum = acc.Add(acc, c.work.total)
				break
			}
			acc.Add(acc, blockWork(hdr.Difficulty))
			if h == 0 {
				break
			}
		}
	}
	if sum == nil {
		var complete bool
		sum, complete = c.fullWorkLocked(tip)
		if !complete {
			// A read error left a partial sum: report it, but never cache it.
			return sum
		}
	}
	c.work.total, c.work.tip, c.work.height = sum, tipID, tip.Height
	return sum
}

// fullWorkWalks counts whole-chain walks (tests assert reorgs and extensions do
// not trigger one).
var fullWorkWalks atomic.Int64

func (c *Chain) fullWorkLocked(tip types.BlockHeader) (*big.Int, bool) {
	fullWorkWalks.Add(1)
	sum := new(big.Int)
	for h := uint64(0); h <= tip.Height; h++ {
		b, err := c.store.BlockAt(h)
		if err != nil {
			return sum, false
		}
		sum.Add(sum, blockWork(b.Header.Difficulty))
		if h == ^uint64(0) {
			break
		}
	}
	return sum, true
}

type workCache struct {
	total  *big.Int
	tip    types.Hash
	height uint64
}

// BlockLocator returns canonical block hashes, newest first: the ten latest
// blocks, then exponentially wider steps back to genesis. A peer finds the
// first hash it knows and so locates the common ancestor in O(log n) hashes.
func (c *Chain) BlockLocator() []types.Hash {
	out, _ := c.BlockLocatorWithHeights()
	return out
}

// BlockLocatorWithHeights is BlockLocator plus the height of each entry.
func (c *Chain) BlockLocatorWithHeights() ([]types.Hash, []uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	tip, ok := c.store.Tip()
	if !ok {
		return nil, nil
	}
	var out []types.Hash
	var heights []uint64
	step := uint64(1)
	h := tip.Height
	for {
		b, err := c.store.BlockAt(h)
		if err != nil {
			break
		}
		out = append(out, types.HeaderID(&b.Header))
		heights = append(heights, h)
		if h == 0 {
			break
		}
		if len(out) >= 10 {
			step *= 2
		}
		if h < step {
			h = 0
		} else {
			h -= step
		}
	}
	return out, heights
}

// HashesAtHeights returns the canonical hashes at the given heights, skipping
// heights the chain does not have.
func (c *Chain) HashesAtHeights(heights []uint64) ([]types.Hash, []uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var hs []types.Hash
	var hts []uint64
	for _, h := range heights {
		b, err := c.store.BlockAt(h)
		if err != nil {
			continue
		}
		hs = append(hs, types.HeaderID(&b.Header))
		hts = append(hts, h)
	}
	return hs, hts
}

// CommonAncestor returns the height of the first locator hash (newest first)
// that is on the canonical chain.
func (c *Chain) CommonAncestor(locator []types.Hash) (height uint64, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, h := range locator {
		if v, found := c.store.HeightOf(h); found {
			return v, true
		}
	}
	return 0, false
}

// BlockHash returns the canonical header hash at height.
func (c *Chain) BlockHash(height uint64) (types.Hash, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	b, err := c.store.BlockAt(height)
	if err != nil {
		return types.Hash{}, false
	}
	return types.HeaderID(&b.Header), true
}

// BlocksFrom returns up to limit canonical blocks starting at height from,
// oldest first.
func (c *Chain) BlocksFrom(from uint64, limit int) []*types.Block {
	c.mu.Lock()
	defer c.mu.Unlock()
	tip, ok := c.store.Tip()
	if !ok || limit <= 0 {
		return nil
	}
	var out []*types.Block
	for h := from; h <= tip.Height && len(out) < limit; h++ {
		b, err := c.store.BlockAt(h)
		if err != nil {
			break
		}
		out = append(out, b)
		if h == ^uint64(0) {
			break
		}
	}
	return out
}
