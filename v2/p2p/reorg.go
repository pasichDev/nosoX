package p2p

import (
	"context"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/noso-project/noso-go/v2/types"
)

// tryReorgFetch is called when a gossip block arrives whose parent we
// don't have on the canonical chain. We request blocks from the peer
// back to our current height, then either apply them via ReorgTo (if
// the fork is heavier) or drop them.
func (n *Libp2pNode) tryReorgFetch(from peer.ID, head *types.Block) {
	if !n.fetcher.tryLock() {
		return // someone else is already fetching
	}
	go func() {
		defer n.fetcher.unlock()
		ctx, cancel := context.WithTimeout(n.ctx, 30*time.Second)
		defer cancel()

		tip, _ := n.chain.Tip()
		myH := tip.Height

		// We know head.Header.PrevHash is not our tip. Walk back from
		// head.Header.Height until we hit a block we already have.
		// In practice the gossiped head is at height tip+1 (one ahead),
		// so we request [myH-3, head.Header.Height-1] as a small window
		// and try to splice.
		from64 := uint64(0)
		if myH > 3 {
			from64 = myH - 3
		}
		to64 := head.Header.Height - 1
		if to64 < from64 {
			to64 = from64
		}
		blocks, err := n.GetBlocks(ctx, from, from64, to64)
		if err != nil {
			n.logger("p2p: reorg fetch from %s: %v", from, err)
			return
		}
		// Append head to the fetched chain.
		blocks = append(blocks, head)
		if err := n.chain.ReorgTo(blocks); err != nil {
			n.logger("p2p: ReorgTo: %v", err)
		}
	}()
}
