package p2p

import (
	"context"
	"errors"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/noso-project/noso-go/v2/chain"
)

// CatchUp brings the local chain up to the peer's tip by repeatedly
// requesting batches via the /noso/sync/1 protocol. Returns when:
//
//	- we are at or past the peer's reported height, or
//	- the peer stops responding / disconnects, or
//	- a returned block fails validation.
//
// Safe to call after a peer's HELLO arrives; cheap to no-op when we
// are already in sync.
func (n *Libp2pNode) CatchUp(ctx context.Context, pid peer.ID, peerHeight uint64) error {
	tip, _ := n.chain.Tip()
	if tip.Height >= peerHeight {
		return nil
	}
	const batch = uint64(64)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		tip, _ := n.chain.Tip()
		if tip.Height >= peerHeight {
			return nil
		}
		from := tip.Height + 1
		to := from + batch - 1
		if to > peerHeight {
			to = peerHeight
		}
		reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		blocks, err := n.GetBlocks(reqCtx, pid, from, to)
		cancel()
		if err != nil {
			return err
		}
		if len(blocks) == 0 {
			return errors.New("p2p: peer returned no blocks")
		}
		applied := 0
		for _, b := range blocks {
			if b.Header.Height < from || b.Header.Height > to {
				continue // peer returned out-of-range
			}
			if err := n.chain.AddBlock(b); err != nil {
				if errors.Is(err, chain.ErrStale) {
					return err // peer is on a different fork
				}
				return err
			}
			applied++
		}
		if applied == 0 {
			return errors.New("p2p: peer returned no usable blocks")
		}
	}
}

// kickColdSync inspects the HELLO message from a peer and starts a
// CatchUp goroutine when the peer is ahead of us. Called from the HELLO
// dispatch.
func (n *Libp2pNode) kickColdSync(pid peer.ID, peerHeight uint64) {
	tip, _ := n.chain.Tip()
	if tip.Height >= peerHeight {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(n.ctx, 5*time.Minute)
		defer cancel()
		if err := n.CatchUp(ctx, pid, peerHeight); err != nil {
			n.logger("p2p: cold-sync from %s aborted at h=%d: %v",
				pid, peerHeight, err)
			return
		}
		n.logger("p2p: cold-sync from %s complete, caught up to height %d", pid, peerHeight)
	}()
}
