package p2p

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"

	"github.com/pasichDev/noso-go/v2/types"
)

// ProtocolSync is the libp2p protocol ID for block-range and locator requests.
// v6 uses the compact binary framing of wire.go.
const ProtocolSync protocol.ID = "/NosoX/sync/v6"

// ErrRateLimited permits bounded retries without treating throttling as
// corrupt chain data.
var ErrRateLimited = errors.New("p2p: rate limit exceeded")

const (
	// A peer must send its request within this long; no slot is held meanwhile.
	syncReadDeadline  = 3 * time.Second
	syncWriteDeadline = 10 * time.Second
	syncMaxSlots      = 8
)

// syncServer limits what the sync service can be made to do: one stream per
// peer, a global slot count taken only after the request is read, a per-peer
// token bucket and a global byte budget.
type syncServer struct {
	slots   chan struct{}
	limiter *rateLimiter
	budget  *byteBudget

	mu      sync.Mutex
	streams map[peer.ID]int
}

func newSyncServer() *syncServer {
	return &syncServer{
		slots:   make(chan struct{}, syncMaxSlots),
		limiter: newRateLimiterRate(2, 16),
		budget:  newByteBudget(8<<20, 32<<20),
		streams: map[peer.ID]int{},
	}
}

func (s *syncServer) enter(p peer.ID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.streams[p] >= 1 {
		return false
	}
	s.streams[p]++
	return true
}

func (s *syncServer) leave(p peer.ID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.streams[p] <= 1 {
		delete(s.streams, p)
		return
	}
	s.streams[p]--
}

func (n *Libp2pNode) installSyncHandler() {
	n.host.SetStreamHandler(ProtocolSync, func(s network.Stream) {
		if !n.launch(func() { n.handleSyncStream(s) }) {
			_ = s.Reset()
		}
	})
}

func (n *Libp2pNode) handleSyncStream(s network.Stream) {
	defer s.Close()
	stop := context.AfterFunc(n.ctx, func() { _ = s.Reset() })
	defer stop()
	pid := s.Conn().RemotePeer()
	if n.book.isBanned(pid) {
		_ = s.Reset()
		return
	}
	if !n.sync.enter(pid) {
		// A well-behaved client opens its next stream the moment it has read the
		// last frame, which can be before our handler has returned. Say "busy"
		// (the client retries) instead of resetting, which it would score as a
		// failure to deliver.
		_ = s.SetDeadline(time.Now().Add(syncWriteDeadline))
		_ = writeFrame(s, []byte{respRateLimited})
		return
	}
	defer n.sync.leave(pid)

	// Read the request first, under a short deadline and without a slot: an
	// idle stream costs one goroutine and nothing else.
	_ = s.SetDeadline(time.Now().Add(syncReadDeadline))
	raw, err := readFrame(s, maxSyncReqBytes)
	if err != nil {
		_ = s.Reset()
		return
	}
	req, err := decodeSyncReq(raw)
	if err != nil {
		n.penalize(pid, penaltyGarbage, "malformed sync request")
		_ = s.Reset()
		return
	}
	_ = s.SetDeadline(time.Now().Add(syncWriteDeadline))

	if !n.sync.limiter.allow(pid) || !n.sync.budget.available() {
		_ = writeFrame(s, []byte{respRateLimited})
		return
	}
	// The slot covers the work (reading the chain, encoding), not the write: a
	// client that reads slowly holds a goroutine and one response, never a slot.
	select {
	case n.sync.slots <- struct{}{}:
	default:
		_ = writeFrame(s, []byte{respRateLimited})
		return
	}

	var out []byte
	switch req.Kind {
	case reqLocator:
		h, ok := n.chain.CommonAncestor(req.Locator)
		out = encodeLocatorResp(locatorResp{Found: ok, Height: h})
	default:
		out, err = encodeBlocksResp(n.buildGetBlocksResp(&req.Blocks))
		if err != nil {
			out, _ = encodeBlocksResp(&GetBlocksResp{Err: "p2p: encode failure"})
		}
	}
	<-n.sync.slots
	n.sync.budget.spend(len(out))
	_ = writeFrame(s, out)
}

// buildGetBlocksResp answers a range request. The range is capped by the
// protocol batch size and the response by the derived wire limit.
func (n *Libp2pNode) buildGetBlocksResp(req *GetBlocksReq) *GetBlocksResp {
	if req.To < req.From {
		return &GetBlocksResp{Err: "p2p: invalid range"}
	}
	if req.To-req.From >= syncBatchMax {
		return &GetBlocksResp{Err: "p2p: range too large"}
	}
	blocks := n.chain.BlocksFrom(req.From, int(req.To-req.From+1))
	size := 16
	out := blocks[:0:0]
	for _, b := range blocks {
		raw, err := encodeBlockMsg(b)
		if err != nil {
			return &GetBlocksResp{Err: "p2p: encode failure"}
		}
		if size+len(raw)+4 > maxSyncRespBytes {
			break
		}
		size += len(raw) + 4
		out = append(out, b)
	}
	return &GetBlocksResp{Blocks: out}
}

// requestFrame runs one request/response exchange with pid.
func (n *Libp2pNode) requestFrame(ctx context.Context, pid peer.ID, req syncReq, maxResp uint32) ([]byte, error) {
	return n.requestFrameWithin(ctx, pid, req, maxResp, requestDeadline)
}

func (n *Libp2pNode) requestFrameWithin(ctx context.Context, pid peer.ID, req syncReq, maxResp uint32, deadline time.Duration) ([]byte, error) {
	s, err := n.host.NewStream(ctx, pid, ProtocolSync)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	stop := context.AfterFunc(ctx, func() { _ = s.Reset() })
	defer stop()
	_ = s.SetDeadline(time.Now().Add(deadline))
	if err := writeFrame(s, encodeSyncReq(req)); err != nil {
		return nil, err
	}
	raw, err := readFrame(s, maxResp)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	return raw, nil
}

// requestDeadline bounds every single request/response exchange, so a peer that
// stalls cannot pin the caller.
const requestDeadline = 15 * time.Second

// GetBlocks asks `pid` for blocks in [from, to].
func (n *Libp2pNode) GetBlocks(ctx context.Context, pid peer.ID, from, to uint64) ([]*types.Block, error) {
	if to < from || to-from >= syncBatchMax {
		return nil, errors.New("p2p: invalid range")
	}
	raw, err := n.requestFrame(ctx, pid, syncReq{Kind: reqBlocks, Blocks: GetBlocksReq{From: from, To: to}}, maxSyncRespBytes)
	if err != nil {
		return nil, err
	}
	resp, err := decodeBlocksResp(raw)
	if err != nil {
		return nil, err
	}
	if resp.Err == ErrRateLimited.Error() {
		return nil, ErrRateLimited
	}
	if resp.Err != "" {
		return nil, errors.New("p2p: peer reported sync error")
	}
	if len(resp.Blocks) > int(to-from+1) {
		return nil, errors.New("p2p: too many blocks")
	}
	for i, b := range resp.Blocks {
		if b == nil || b.Header.Height != from+uint64(i) {
			return nil, errors.New("p2p: noncontiguous block response")
		}
	}
	return resp.Blocks, nil
}

// ancestor is a block both chains share.
type ancestor struct {
	height uint64
	hash   types.Hash
}

// FindAncestor returns the height of the newest block we share with pid.
func (n *Libp2pNode) FindAncestor(ctx context.Context, pid peer.ID) (uint64, error) {
	a, err := n.findAncestor(ctx, pid)
	return a.height, err
}

// locate sends one locator (newest first) and returns the index of the first
// entry pid has on its canonical chain. The answer is validated against the
// heights we put in THIS request, never against our current chain, so a local
// reorganisation while the request is in flight cannot make an honest peer look
// like it lied.
func (n *Libp2pNode) locate(ctx context.Context, pid peer.ID, hashes []types.Hash, heights []uint64) (int, error) {
	raw, err := n.requestFrameWithin(ctx, pid, syncReq{Kind: reqLocator, Locator: hashes}, 16, locatorDeadline)
	if err != nil {
		return 0, err
	}
	resp, err := decodeLocatorResp(raw)
	if err != nil {
		return 0, err
	}
	if !resp.Found {
		return 0, errNoCommonAncestor
	}
	for i, h := range heights {
		if h == resp.Height {
			return i, nil
		}
	}
	return 0, errBadAncestor
}

// findAncestor finds the exact newest block we share with pid. The sparse
// locator narrows it to a gap between two of its entries (up to 512 blocks near
// the reorg limit); follow-up locators of up to 64 evenly spread heights inside
// the gap then refine it, two rounds for the widest gap, so a fork anywhere
// within MaxReorgBlocks is found at its true depth.
func (n *Libp2pNode) findAncestor(ctx context.Context, pid peer.ID) (ancestor, error) {
	hashes, heights := n.chain.BlockLocatorWithHeights()
	if len(hashes) == 0 {
		return ancestor{}, errors.New("p2p: empty chain")
	}
	idx, err := n.locate(ctx, pid, hashes, heights)
	if err != nil {
		return ancestor{}, err
	}
	lo, loHash := heights[idx], hashes[idx]
	if idx == 0 {
		return ancestor{lo, loHash}, nil
	}
	hi := heights[idx-1] // not on pid's chain
	for hi-lo > 1 {
		cand := spreadHeights(lo, hi, maxLocatorEntries-1)
		hs, hts := n.chain.HashesAtHeights(cand)
		hs, hts = append(hs, loHash), append(hts, lo)
		j, err := n.locate(ctx, pid, hs, hts)
		if err != nil {
			return ancestor{}, err
		}
		if j > 0 {
			hi = hts[j-1]
		}
		lo, loHash = hts[j], hs[j]
	}
	return ancestor{lo, loHash}, nil
}

// spreadHeights returns up to k heights strictly between lo and hi, newest
// first, evenly spaced (every height when the gap is small enough).
func spreadHeights(lo, hi uint64, k int) []uint64 {
	gap := hi - lo - 1 // heights strictly inside
	if gap == 0 {
		return nil
	}
	step := (gap + uint64(k) - 1) / uint64(k)
	var out []uint64
	for h := hi - 1; h > lo; {
		out = append(out, h)
		if h-lo <= step {
			break
		}
		h -= step
	}
	return out
}

var (
	errNoCommonAncestor = errors.New("p2p: peer shares no block with us (different genesis)")
	errBadAncestor      = errors.New("p2p: peer returned an ancestor outside our locator")
)
