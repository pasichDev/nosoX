package p2p

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pasichDev/noso-go/v2/types"
	"io"
	"math"
	"testing"
	"time"
)

func TestDecoderRejectsOversizedPayload(t *testing.T) {
	if _, e := decodeBlockMsg(bytes.Repeat([]byte(" "), maxWireBytes+1)); e == nil {
		t.Fatal("oversized accepted")
	}
}
func TestDecoderRejectsTrailingPayload(t *testing.T) {
	raw, e := encodeBlockMsg(&types.Block{})
	if e != nil {
		t.Fatal(e)
	}
	raw = append(raw, raw...)
	if _, e = decodeBlockMsg(raw); e == nil {
		t.Fatal("trailing message accepted")
	}
}
func TestLimiterBoundsPeerRecords(t *testing.T) {
	r := newRateLimiter()
	for i := 0; i < 10000; i++ {
		r.allow(peerID(i))
	}
	if len(r.buckets) > 4096 {
		t.Fatalf("unbounded peer map: %d", len(r.buckets))
	}
}
func peerID(i int) peer.ID { return peer.ID(fmt.Sprint(i)) }
func TestSyncRangeRejectsOverflow(t *testing.T) {
	r := buildGetBlocksResp(nil, &GetBlocksReq{From: 0, To: math.MaxUint64})
	if r.Err == "" {
		t.Fatal("overflow range accepted")
	}
}

func TestSyncRejectsMalformedPeerResponses(t *testing.T) {
	g := easyGenesis()
	a, _, _, stopA := bringUpNode(t, "malicious", g)
	defer stopA()
	b, _, _, stopB := bringUpNode(t, "client", g)
	defer stopB()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if e := b.ConnectSeed(ctx, a.Addrs()[0]); e != nil {
		t.Fatal(e)
	}
	for _, blocks := range [][]*types.Block{{nil}, {{Header: types.BlockHeader{Height: 2}}}, {{Header: types.BlockHeader{Height: 1}}, {Header: types.BlockHeader{Height: 3}}}} {
		a.host.SetStreamHandler(ProtocolSync, func(s network.Stream) {
			defer s.Close()
			_, _ = readFrame(s, 1024)
			raw, _ := json.Marshal(GetBlocksResp{Blocks: blocks})
			_ = writeFrame(s, raw)
		})
		if _, e := b.GetBlocks(ctx, a.host.ID(), 1, 2); e == nil {
			t.Fatal("malformed block sequence accepted")
		}
	}
}
func TestSyncCancellationInterruptsRead(t *testing.T) {
	g := easyGenesis()
	a, _, _, stopA := bringUpNode(t, "stall", g)
	defer stopA()
	b, _, _, stopB := bringUpNode(t, "client", g)
	defer stopB()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if e := b.ConnectSeed(ctx, a.Addrs()[0]); e != nil {
		t.Fatal(e)
	}
	a.host.SetStreamHandler(ProtocolSync, func(s network.Stream) { defer s.Close(); _, _ = readFrame(s, 1024); _, _ = io.Copy(io.Discard, s) })
	req, stop := context.WithTimeout(ctx, 50*time.Millisecond)
	defer stop()
	start := time.Now()
	if _, e := b.GetBlocks(req, a.host.ID(), 1, 1); e == nil {
		t.Fatal("stalled response succeeded")
	}
	if time.Since(start) > time.Second {
		t.Fatal("request cancellation did not interrupt stream read")
	}
}

func TestColdSyncRateLimitWaitHonorsCancellation(t *testing.T) {
	g := easyGenesis()
	a, _, _, stopA := bringUpNode(t, "limited", g)
	defer stopA()
	b, _, _, stopB := bringUpNode(t, "client", g)
	defer stopB()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if e := b.ConnectSeed(ctx, a.Addrs()[0]); e != nil {
		t.Fatal(e)
	}
	a.host.SetStreamHandler(ProtocolSync, func(s network.Stream) {
		defer s.Close()
		_, _ = readFrame(s, 1024)
		raw, _ := json.Marshal(GetBlocksResp{Err: ErrRateLimited.Error()})
		_ = writeFrame(s, raw)
	})
	if _, e := b.GetBlocks(ctx, a.host.ID(), 1, 1); !errors.Is(e, ErrRateLimited) {
		t.Fatalf("rate limit not classified: %v", e)
	}
	req, stop := context.WithTimeout(ctx, 50*time.Millisecond)
	defer stop()
	if e := b.CatchUp(req, a.host.ID(), 1); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatalf("backoff cancellation: %v", e)
	}
}

func TestDecoderV4NativeEnvelope(t *testing.T) {
	valid := &types.Block{Header: types.BlockHeader{Height: 1}, Inputs: []types.Input{{LegacyPubKey: string(make([]byte, 88))}}, Outputs: []types.Output{{RangeProof: make([]byte, types.MaxRangeProofBytes)}}}
	for _, mutate := range []func(*types.Block){
		nil,
		func(b *types.Block) { b.Inputs[0].LegacyPubKey += "x" },
		func(b *types.Block) { b.Inputs = make([]types.Input, types.MaxBlockInputs+1) },
		func(b *types.Block) { b.Outputs = make([]types.Output, types.MaxBlockOutputs+1) },
		func(b *types.Block) { b.Kernels = make([]types.Kernel, types.MaxBlockKernels+1) },
		func(b *types.Block) { b.Outputs[0].RangeProof = append(b.Outputs[0].RangeProof, 0) },
	} {
		raw, err := encodeBlockMsg(valid)
		if err != nil {
			t.Fatal(err)
		}
		var b types.Block
		if err := json.Unmarshal(raw, &b); err != nil {
			t.Fatal(err)
		}
		if mutate != nil {
			mutate(&b)
		}
		raw, err = encodeBlockMsg(&b)
		if err != nil {
			t.Fatal(err)
		}
		_, err = decodeBlockMsg(raw)
		if (err != nil) != (mutate != nil) {
			t.Fatalf("block structural envelope: %v", err)
		}
		raw, err = encodeTxMsg(&types.Transaction{Inputs: b.Inputs, Outputs: b.Outputs, Kernels: b.Kernels})
		if err != nil {
			t.Fatal(err)
		}
		_, err = decodeTxMsg(raw)
		if (err != nil) != (mutate != nil) {
			t.Fatalf("transaction structural envelope: %v", err)
		}
	}
}
