package p2p

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"

	"github.com/pasichDev/noso-go/v2/chain"
	"github.com/pasichDev/noso-go/v2/types"
)

// ProtocolSync is the libp2p protocol ID for block-range requests.
const ProtocolSync protocol.ID = "/noso/sync/2"

// ErrRateLimited permits bounded cold-sync retries without treating throttling
// as corrupt chain data.
var ErrRateLimited = errors.New("p2p: rate limit exceeded")

// GetBlocksReq asks for a range of blocks. Both ends inclusive.
type GetBlocksReq struct {
	From uint64
	To   uint64
}

// GetBlocksResp is the response: a serialized slice of blocks.
type GetBlocksResp struct {
	Blocks []*types.Block
	Err    string // non-empty means the responder failed (e.g. out of range)
}

// installSyncHandler registers the protocol handler on the libp2p host
// so peers can request block ranges from us.
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
	select {
	case n.syncSlots <- struct{}{}:
		defer func() { <-n.syncSlots }()
	default:
		_ = s.Reset()
		return
	}
	_ = s.SetDeadline(time.Now().Add(30 * time.Second))

	// Per-peer rate limit: a single peer cannot hammer /noso/sync/1.
	// Default 1 batch per 5 s with a burst of 3 — enough for fresh
	// nodes to catch up via concurrent requests, slow enough that a
	// malicious peer cannot saturate bandwidth.
	if n.limiter != nil && !n.limiter.allow(s.Conn().RemotePeer()) {
		resp := &GetBlocksResp{Err: ErrRateLimited.Error()}
		var buf bytes.Buffer
		_ = json.NewEncoder(&buf).Encode(resp)
		var lp [4]byte
		binary.BigEndian.PutUint32(lp[:], uint32(buf.Len()))
		_, _ = s.Write(lp[:])
		_, _ = s.Write(buf.Bytes())
		return
	}

	var lenBuf [4]byte
	if _, err := io.ReadFull(s, lenBuf[:]); err != nil {
		return
	}
	reqLen := binary.BigEndian.Uint32(lenBuf[:])
	if reqLen > 1024 {
		return
	}
	reqBytes := make([]byte, reqLen)
	if _, err := io.ReadFull(s, reqBytes); err != nil {
		return
	}
	var req GetBlocksReq
	if err := decodeWire(reqBytes, &req, 1024); err != nil {
		return
	}
	resp := buildGetBlocksResp(n.chain, &req)
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(resp); err != nil {
		return
	}
	if buf.Len() > 16<<20 {
		return
	}
	var lp [4]byte
	binary.BigEndian.PutUint32(lp[:], uint32(buf.Len()))
	_, _ = s.Write(lp[:])
	_, _ = s.Write(buf.Bytes())
}

func buildGetBlocksResp(c *chain.Chain, req *GetBlocksReq) *GetBlocksResp {
	if req.To < req.From {
		return &GetBlocksResp{Err: "p2p: invalid range"}
	}
	if req.To-req.From >= 64 {
		return &GetBlocksResp{Err: "p2p: range too large"}
	}
	out := make([]*types.Block, 0, req.To-req.From+1)
	size := 1024
	tip, _ := c.Tip()
	for h := req.From; h <= req.To && h <= tip.Height; h++ {
		// Full block — header + inputs + outputs + kernels — so the
		// requesting peer can re-run validation and apply via ReorgTo.
		b, ok := c.BlockByHeight(h)
		if !ok {
			break
		}
		raw, err := json.Marshal(b)
		if err != nil {
			return &GetBlocksResp{Err: "p2p: encode failure"}
		}
		if size+len(raw) > 16<<20 {
			if len(out) == 0 {
				return &GetBlocksResp{Err: "p2p: block exceeds wire limit"}
			}
			break
		}
		size += len(raw) + 1
		out = append(out, b)
		if h == req.To {
			break
		}
	}
	return &GetBlocksResp{Blocks: out}
}

// GetBlocks asks `pid` for blocks in [from, to]. Used by the reorg
// fetcher when AddBlock returns ErrStale.
func (n *Libp2pNode) GetBlocks(ctx context.Context, pid peer.ID, from, to uint64) ([]*types.Block, error) {
	if to < from || to-from >= 64 {
		return nil, errors.New("p2p: invalid range")
	}
	s, err := n.host.NewStream(ctx, pid, ProtocolSync)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	stop := context.AfterFunc(ctx, func() { _ = s.Reset() })
	defer stop()
	_ = s.SetDeadline(time.Now().Add(15 * time.Second))

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(GetBlocksReq{From: from, To: to}); err != nil {
		return nil, err
	}
	var lp [4]byte
	binary.BigEndian.PutUint32(lp[:], uint32(buf.Len()))
	if _, err := s.Write(lp[:]); err != nil {
		return nil, err
	}
	if _, err := s.Write(buf.Bytes()); err != nil {
		return nil, err
	}

	var resplp [4]byte
	if _, err := io.ReadFull(s, resplp[:]); err != nil {
		return nil, err
	}
	respLen := binary.BigEndian.Uint32(resplp[:])
	if respLen > 16<<20 { // 16 MiB hard cap
		return nil, errors.New("p2p: oversized response")
	}
	respBytes := make([]byte, respLen)
	if _, err := io.ReadFull(s, respBytes); err != nil {
		return nil, err
	}
	var resp GetBlocksResp
	if err := decodeWire(respBytes, &resp, 16<<20); err != nil {
		return nil, err
	}
	if len(resp.Err) > 1024 {
		return nil, errors.New("p2p: oversized remote error")
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
		if err := checkBody(b.Inputs, b.Outputs, b.Kernels); err != nil {
			return nil, err
		}
	}
	return resp.Blocks, nil
}

// reorgFetcher keeps a single in-flight request at a time to avoid
// thrashing on a fork.
type reorgFetcher struct {
	mu      sync.Mutex
	pending bool
}

func (f *reorgFetcher) tryLock() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pending {
		return false
	}
	f.pending = true
	return true
}

func (f *reorgFetcher) unlock() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pending = false
}
