package p2p

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/pasichDev/nosoX/v2/chain"
	"github.com/pasichDev/nosoX/v2/types"
)

// The sync manager makes the node converge on the chain with the most
// accumulated work, never on height:
//
//   - every peer advertises cumulative work in hello; the manager repeatedly
//     picks the connected peer with the most work above ours;
//   - it finds the common ancestor with an exponential block locator (up to the
//     1024-block reorg limit), fetches the peer's blocks in 64-block batches and
//     either extends the chain or hands the fork to ReorgTo once the fork's
//     declared work beats ours;
//   - every request has its own deadline; a peer that fails to deliver, lies
//     about its work or serves PROVABLY invalid blocks is scored, backed off and
//     eventually banned, and the next peer is tried at once. A failure that
//     depends on our own state (our tip moved, our clock, our disk, our limits,
//     a busy server) never costs the peer anything;
//   - peers are ranked by work they have actually delivered before claims alone,
//     so a free identity advertising huge work cannot starve honest sync;
//   - there is no session cap: a node any distance behind keeps going.

const (
	syncTick        = 10 * time.Second
	statusMaxAge    = 30 * time.Second
	refreshMinGap   = 3 * time.Second
	maxSessionsEach = 16
	rlRetries       = 4
	rlFirstWait     = 250 * time.Millisecond
	maxBackoff      = 10 * time.Minute
)

var (
	errTooDeepFork = errors.New("p2p: peer's fork is deeper than the reorg limit")
	errRaced       = errors.New("p2p: our tip moved during sync")
	errPeerMoved   = errors.New("p2p: peer's chain moved during sync")
	errLocal       = errors.New("p2p: sync stopped by a local condition")
)

// badKey names a (peer, claimed tip) pair. Marks are per peer: a hash a peer
// merely asserted must never influence how we treat any other peer.
type badKey struct {
	pid  peer.ID
	hash types.Hash
}

const (
	locatorDeadline = 5 * time.Second
	helloGrace      = 10 * time.Second
	badTipTTL       = 10 * time.Minute
	// tipFresh is how recent our tip must be for us to trust our own view of the
	// network without a peer at our work level to confirm it.
	tipFresh = 10 * types.TargetBlockTimeSeconds
)

// kickSync wakes the sync loop.
func (n *Libp2pNode) kickSync() {
	select {
	case n.syncKick <- struct{}{}:
	default:
	}
}

func (n *Libp2pNode) syncLoop() {
	defer n.wg.Done()
	tick := time.NewTicker(syncTick)
	defer tick.Stop()
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-tick.C:
			n.refreshStatuses()
		case <-n.syncKick:
		}
		n.syncRound()
	}
}

// refreshStatuses re-queries peers whose advertised state is stale, so a peer
// that mined or reorged since hello is noticed.
func (n *Libp2pNode) refreshStatuses() {
	now := time.Now()
	for _, pid := range n.host.Network().Peers() {
		n.book.mu.Lock()
		ps := n.book.get(pid)
		stale := !ps.haveStatus || now.Sub(ps.statusAt) > statusMaxAge
		if stale {
			ps.refreshAt = now
		}
		n.book.mu.Unlock()
		if stale {
			n.launch(func() { n.queryStatus(pid) })
		}
	}
}

// noteFork is called when gossip shows a block we cannot attach. It asks the
// sender for its current status, which wakes the sync loop if it is heavier.
func (n *Libp2pNode) noteFork(pid peer.ID) {
	if pid == "" || pid == n.host.ID() {
		return
	}
	now := time.Now()
	n.book.mu.Lock()
	ps := n.book.get(pid)
	skip := now.Sub(ps.refreshAt) < refreshMinGap
	if !skip {
		ps.refreshAt = now
	}
	n.book.mu.Unlock()
	if !skip {
		n.launch(func() { n.queryStatus(pid) })
	}
}

// bestPeer returns the connected, eligible peer to sync from next. Peers that
// have delivered blocks before rank above peers that only claim work; within a
// rank the highest claim wins.
func (n *Libp2pNode) bestPeer() (peer.ID, Status, bool) {
	mine := n.chain.TotalWork()
	now := time.Now()
	var (
		bestID     peer.ID
		best       Status
		bestProven bool
		found      bool
	)
	for _, pid := range n.host.Network().Peers() {
		if n.host.Network().Connectedness(pid) != network.Connected {
			continue
		}
		n.book.mu.Lock()
		ps, ok := n.book.peers[pid]
		var st Status
		proven := false
		eligible := ok && ps.haveStatus && !now.Before(ps.retryAt)
		if eligible {
			st, proven = ps.status, ps.delivered > 0
		}
		n.book.mu.Unlock()
		if !eligible || n.book.isBanned(pid) || st.TotalWork.Cmp(mine) <= 0 || n.isBadTip(pid, st.TipHash) {
			continue
		}
		better := !found || (proven && !bestProven) || (proven == bestProven && st.TotalWork.Cmp(best.TotalWork) > 0)
		if better {
			bestID, best, bestProven, found = pid, st, proven, true
		}
	}
	return bestID, best, found
}

// syncRound syncs from the best peer, then the next best, until nobody has more
// work than we do or every candidate has failed.
func (n *Libp2pNode) syncRound() {
	for i := 0; i < maxSessionsEach && n.ctx.Err() == nil; i++ {
		pid, st, ok := n.bestPeer()
		if !ok {
			return
		}
		err := n.syncSession(n.ctx, pid, st)
		n.book.mu.Lock()
		ps := n.book.get(pid)
		switch {
		case err == nil:
			ps.fails, ps.retryAt = 0, time.Time{}
		case errors.Is(err, errRaced), errors.Is(err, errPeerMoved):
			// Not the peer's fault; look again soon, but not forever.
			ps.fails++
			ps.retryAt = time.Now().Add(time.Second << min(ps.fails, 6))
		case errors.Is(err, ErrRateLimited), errors.Is(err, errLocal):
			// A busy server or our own condition is not a failure to deliver:
			// ask again shortly, without counting a strike.
			ps.retryAt = time.Now().Add(5*time.Second + time.Duration(rand.Int63n(int64(5*time.Second))))
		default:
			ps.fails++
			wait := 5 * time.Second << min(ps.fails, 8)
			if wait > maxBackoff {
				wait = maxBackoff
			}
			ps.retryAt = time.Now().Add(wait)
		}
		n.book.mu.Unlock()
		if err != nil && !errors.Is(err, context.Canceled) {
			n.logger("p2p: sync from %s: %v", pid, err)
		}
	}
}

// retryRL runs f, waiting and retrying (bounded) while the peer rate-limits us.
func retryRL(ctx context.Context, f func() error) error {
	wait := rlFirstWait
	for i := 0; ; i++ {
		err := f()
		if !errors.Is(err, ErrRateLimited) || i >= rlRetries {
			return err
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
		wait *= 2
	}
}

// localWorkAbove sums the declared work of our canonical blocks above height.
func (n *Libp2pNode) localWorkAbove(height uint64) *big.Int {
	w := new(big.Int)
	tip, _ := n.chain.Tip()
	for h := tip.Height; h > height; h-- {
		hdr, ok := n.chain.HeaderByHeight(h)
		if !ok {
			break
		}
		w.Add(w, chain.BlockWork(hdr.Difficulty))
	}
	return w
}

// blameBlock decides what a block we could not append costs the peer that
// served it. Only a rejection that is provable from the block and the parent it
// names bans; our tip moving, our clock, our limits and our disk never do.
func (n *Libp2pNode) blameBlock(pid peer.ID, claim Status, b *types.Block, err error) error {
	switch {
	case chain.IsPeerFault(err):
		n.markBadTip(pid, claim.TipHash)
		n.penalize(pid, penaltyInvalid, "invalid block: "+err.Error())
		return err
	case errors.Is(err, chain.ErrStale):
		return fmt.Errorf("%w: %v", errRaced, err)
	case errors.Is(err, chain.ErrFutureTimestamp):
		n.noteFutureBlock(pid, b.Header.Timestamp)
		return fmt.Errorf("%w: %v", errLocal, err)
	}
	return fmt.Errorf("%w: %v", errLocal, err)
}

// blameFork is blameBlock for a rejected fork hand-off.
func (n *Libp2pNode) blameFork(pid peer.ID, claim Status, suffix []*types.Block, err error) error {
	switch {
	case chain.IsPeerFault(err):
		n.markBadTip(pid, claim.TipHash)
		n.penalize(pid, penaltyInvalid, "invalid fork: "+err.Error())
		return err
	case errors.Is(err, chain.ErrLowWork), errors.Is(err, chain.ErrStale), errors.Is(err, chain.ErrUnknownAnc):
		// Our tip moved while we fetched, or the peer's did: look again.
		return fmt.Errorf("%w: %v", errRaced, err)
	case errors.Is(err, chain.ErrCheckpoint), errors.Is(err, chain.ErrTooDeep):
		n.markBadTip(pid, claim.TipHash)
		return err
	case errors.Is(err, chain.ErrFutureTimestamp):
		if len(suffix) > 0 {
			n.noteFutureBlock(pid, suffix[len(suffix)-1].Header.Timestamp)
		}
	}
	return fmt.Errorf("%w: %v", errLocal, err)
}

// syncSession brings us towards pid's chain. claim is what pid advertised.
func (n *Libp2pNode) syncSession(ctx context.Context, pid peer.ID, claim Status) error {
	var anc ancestor
	err := retryRL(ctx, func() (e error) { anc, e = n.findAncestor(ctx, pid); return })
	switch {
	case err == nil:
	case errors.Is(err, ErrRateLimited):
		return err // a busy server is not a failure to deliver
	case errors.Is(err, errNoCommonAncestor), errors.Is(err, errBadAncestor), errors.Is(err, errWire):
		n.penalize(pid, penaltyInvalid, err.Error())
		return err
	default:
		if ctx.Err() == nil {
			n.penalize(pid, penaltyUndelivered, "locator: "+err.Error())
		}
		return err
	}
	tip, _ := n.chain.Tip()
	if tip.Height > anc.height && tip.Height-anc.height > types.MaxReorgBlocks {
		// The ancestor is exact, so this fork really is beyond the reorg limit.
		// That is a property of the two chains, not proof of misbehaviour: only
		// this peer's claim is set aside (keyed per peer, so it can neither
		// poison honest peers nor outlive its TTL).
		n.markBadTip(pid, claim.TipHash)
		n.logger("p2p: %s advertises more work but diverges %d blocks back (limit %d); this node cannot follow it without a resync", pid, tip.Height-anc.height, types.MaxReorgBlocks)
		return errTooDeepFork
	}
	fork := anc.height < tip.Height
	myWork := n.localWorkAbove(anc.height)
	suffixWork := new(big.Int)
	var suffix []*types.Block
	next := anc.height + 1
	expectParent := anc.hash
	accepted := uint64(0)
	defer func() {
		if accepted > 0 {
			n.creditPeer(pid, accepted)
		}
	}()

	for next <= claim.Height && ctx.Err() == nil {
		first := next
		to := min(next+syncBatchMax-1, claim.Height)
		var blocks []*types.Block
		err := retryRL(ctx, func() (e error) { blocks, e = n.GetBlocks(ctx, pid, next, to); return })
		if err != nil {
			if ctx.Err() == nil && !errors.Is(err, ErrRateLimited) {
				pts := penaltyUndelivered
				if errors.Is(err, errWire) {
					pts = penaltyInvalid
				}
				n.penalize(pid, pts, "blocks: "+err.Error())
			}
			return err
		}
		if len(blocks) == 0 {
			break // the peer has nothing more to give
		}
		// A batch is one atomic snapshot of the peer's chain, so blocks inside it
		// that do not link are provable misbehaviour. Where the batch starts is
		// not: the peer may simply have moved since the last answer.
		for i := 1; i < len(blocks); i++ {
			if blocks[i].Header.PrevHash != types.HeaderID(&blocks[i-1].Header) {
				n.markBadTip(pid, claim.TipHash)
				n.penalize(pid, penaltyInvalid, "batch does not link")
				return errors.New("p2p: peer served a batch that does not link")
			}
		}
		if blocks[0].Header.PrevHash != expectParent {
			n.penalize(pid, penaltyMoved, "batch does not continue its chain")
			return errPeerMoved
		}
		expectParent = types.HeaderID(&blocks[len(blocks)-1].Header)
		for _, b := range blocks {
			if !fork {
				if hdr, ok := n.chain.HeaderByHeight(b.Header.Height); ok && types.HeaderID(&hdr) == types.HeaderID(&b.Header) {
					continue // gossip delivered it meanwhile
				}
				if err := n.chain.AddBlock(b); err != nil {
					return n.blameBlock(pid, claim, b, err)
				}
				accepted++
				continue
			}
			suffix = append(suffix, b)
			suffixWork.Add(suffixWork, chain.BlockWork(b.Header.Difficulty))
		}
		next = blocks[len(blocks)-1].Header.Height + 1
		if fork {
			if len(suffix) > types.MaxReorgBlocks {
				n.markBadTip(pid, claim.TipHash)
				return errTooDeepFork
			}
			// Cheap pre-check on declared work; ReorgTo does the full validation.
			if suffixWork.Cmp(myWork) > 0 {
				if err := n.chain.ReorgTo(suffix); err != nil {
					return n.blameFork(pid, claim, suffix, err)
				}
				accepted += uint64(len(suffix))
				fork, suffix = false, nil
				n.logger("p2p: reorganised onto the heavier chain of %s (ancestor %d)", pid, anc.height)
			}
		}
		if uint64(len(blocks)) < to-first+1 {
			break // short answer: the peer's chain ends here
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if n.chain.TotalWork().Cmp(claim.TotalWork) < 0 {
		// It advertised work it could not back with blocks.
		n.markBadTip(pid, claim.TipHash)
		n.penalize(pid, penaltyWorkLie, "advertised work it did not deliver")
		return errors.New("p2p: peer did not deliver the work it advertised")
	}
	return nil
}

// creditPeer records blocks a peer served that we accepted.
func (n *Libp2pNode) creditPeer(pid peer.ID, blocks uint64) {
	n.book.mu.Lock()
	n.book.get(pid).delivered += blocks
	n.book.mu.Unlock()
	n.remember(pid) // a peer that proved itself may enter the address book
}

// Synced reports whether this node may treat its chain as the network's. A
// miner must not start (and keeps asking, it is not a one-shot) unless:
//   - at least one peer has told us its state, and no peer that is connected,
//     not banned and not set aside advertises more work than we have;
//   - no connected peer is still in its handshake (within helloGrace), so the
//     first fast answer cannot decide for the rest;
//   - and either our tip is recent, or a peer at our work level or above
//     confirms it. A lagging low-work peer alone says nothing about the network.
func (n *Libp2pNode) Synced() bool {
	mine := n.chain.TotalWork()
	tip, _ := n.chain.Tip()
	now := time.Now()
	known, confirmed := false, false
	for _, pid := range n.host.Network().Peers() {
		if n.book.isBanned(pid) {
			continue
		}
		n.book.mu.Lock()
		ps, ok := n.book.peers[pid]
		var st Status
		have := ok && ps.haveStatus
		if have {
			st = ps.status
		}
		n.book.mu.Unlock()
		if !have {
			opened := now
			if conns := n.host.Network().ConnsToPeer(pid); len(conns) > 0 {
				opened = conns[0].Stat().Opened
			}
			if now.Sub(opened) < helloGrace {
				return false // handshake in flight: wait for it
			}
			continue
		}
		if n.isBadTip(pid, st.TipHash) {
			continue // this peer failed to back its claim; it does not hold us back
		}
		known = true
		if st.TotalWork.Cmp(mine) > 0 {
			return false
		}
		if st.TotalWork.Cmp(mine) == 0 {
			confirmed = true
		}
	}
	if !known {
		return false
	}
	return confirmed || now.Unix()-tip.Timestamp < tipFresh
}

func (n *Libp2pNode) markBadTip(pid peer.ID, h types.Hash) {
	n.badMu.Lock()
	defer n.badMu.Unlock()
	now := time.Now()
	if len(n.badTips) >= 256 {
		for k, t := range n.badTips {
			if now.After(t) {
				delete(n.badTips, k)
			}
		}
		if len(n.badTips) >= 256 {
			clear(n.badTips)
		}
	}
	n.badTips[badKey{pid, h}] = now.Add(badTipTTL)
}

func (n *Libp2pNode) isBadTip(pid peer.ID, h types.Hash) bool {
	n.badMu.Lock()
	defer n.badMu.Unlock()
	k := badKey{pid, h}
	t, ok := n.badTips[k]
	if ok && time.Now().After(t) {
		delete(n.badTips, k)
		return false
	}
	return ok
}

// skewTracker notices blocks stamped further in the future than consensus
// allows, from several distinct peers: more likely our clock than theirs.
type skewTracker struct {
	mu     sync.Mutex
	peers  map[peer.ID]time.Time
	warned time.Time
}

// noteFutureBlock records that pid served a block stamped beyond the allowed
// future drift and warns, at most every 10 minutes, once two peers agree.
func (n *Libp2pNode) noteFutureBlock(pid peer.ID, ts int64) {
	n.skew.note(pid, ts, time.Now(), func(ahead time.Duration) {
		n.logger("WARNING: peers keep serving blocks stamped %s ahead of this machine's clock (limit %ds). The local clock is probably behind: fix it (NTP) or this node will reject the honest chain.", ahead.Round(time.Second), types.MaxFutureDriftSeconds)
	})
}

func (t *skewTracker) note(pid peer.ID, ts int64, now time.Time, warn func(time.Duration)) {
	ahead := time.Duration(ts-now.Unix()) * time.Second
	if ahead <= time.Duration(types.MaxFutureDriftSeconds)*time.Second {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.peers == nil {
		t.peers = map[peer.ID]time.Time{}
	}
	t.peers[pid] = now
	distinct := 0
	for p, at := range t.peers {
		if now.Sub(at) > 10*time.Minute {
			delete(t.peers, p)
			continue
		}
		distinct++
	}
	if distinct >= 2 && now.Sub(t.warned) > 10*time.Minute {
		t.warned = now
		go warn(ahead)
	}
}
