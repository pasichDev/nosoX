package p2p

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pasichDev/nosoX/v2/chain"
	"github.com/pasichDev/nosoX/v2/mempool"
	"github.com/pasichDev/nosoX/v2/types"
	"io"
	"math"
	"testing"
	"time"
)

func TestDecoderRejectsOversizedPayload(t *testing.T) {
	if _, e := decodeBlockMsg(bytes.Repeat([]byte(" "), maxBlockWireBytes+1)); e == nil {
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
	r := (&Libp2pNode{}).buildGetBlocksResp(&GetBlocksReq{From: 0, To: math.MaxUint64})
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
	hdr := func(h uint64) []byte {
		w := &wbuf{}
		putHeader(w, &types.BlockHeader{Height: h})
		w.u8(0)
		w.u8(0)
		w.u8(0)
		return w.b
	}
	frame := func(blocks ...[]byte) []byte {
		w := &wbuf{}
		w.u8(respOK)
		w.u8(uint8(len(blocks)))
		for _, b := range blocks {
			w.u32(uint32(len(b)))
			w.raw(b)
		}
		return w.b
	}
	for _, raw := range [][]byte{frame(nil), frame(hdr(2)), frame(hdr(1), hdr(3)), {respOK, 200}, {9}} {
		a.host.SetStreamHandler(ProtocolSync, func(s network.Stream) {
			defer s.Close()
			_, _ = readFrame(s, maxSyncReqBytes)
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
	a.host.SetStreamHandler(ProtocolSync, func(s network.Stream) {
		defer s.Close()
		_, _ = readFrame(s, maxSyncReqBytes)
		_, _ = io.Copy(io.Discard, s)
	})
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
		_, _ = readFrame(s, maxSyncReqBytes)
		_ = writeFrame(s, []byte{respRateLimited})
	})
	if _, e := b.GetBlocks(ctx, a.host.ID(), 1, 1); !errors.Is(e, ErrRateLimited) {
		t.Fatalf("rate limit not classified: %v", e)
	}
	req, stop := context.WithTimeout(ctx, 50*time.Millisecond)
	defer stop()
	if e := retryRL(req, func() error { _, err := b.GetBlocks(req, a.host.ID(), 1, 1); return err }); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatalf("backoff cancellation: %v", e)
	}
}

func TestDecoderNativeEnvelope(t *testing.T) {
	valid := func() *types.Block {
		return &types.Block{Header: types.BlockHeader{Height: 1}, Inputs: []types.Input{{}}, Outputs: []types.Output{{RangeProof: make([]byte, types.MaxRangeProofBytes)}}}
	}
	for i, mutate := range []func(*types.Block){
		nil,
		func(b *types.Block) { b.Inputs = make([]types.Input, types.MaxBlockInputs+1) },
		func(b *types.Block) { b.Outputs = make([]types.Output, types.MaxBlockOutputs+1) },
		func(b *types.Block) { b.Kernels = make([]types.Kernel, types.MaxBlockKernels+1) },
		func(b *types.Block) { b.Outputs[0].RangeProof = append(b.Outputs[0].RangeProof, 0) },
	} {
		b := valid()
		if mutate != nil {
			mutate(b)
		}
		raw, err := encodeBlockMsg(b)
		if err == nil {
			_, err = decodeBlockMsg(raw)
		}
		if (err != nil) != (mutate != nil) {
			t.Fatalf("case %d: block structural envelope: %v", i, err)
		}
		raw, err = encodeTxMsg(&types.Transaction{Inputs: b.Inputs, Outputs: b.Outputs, Kernels: b.Kernels})
		if err == nil {
			_, err = decodeTxMsg(raw)
		}
		if (err != nil) != (mutate != nil) {
			t.Fatalf("case %d: transaction structural envelope: %v", i, err)
		}
	}
}

// A relay-policy refusal is never the sender's fault; an invalid transaction is.
func TestGossipTxAdmissionClassification(t *testing.T) {
	cases := []struct {
		name      string
		err       error
		local     bool
		want      pubsub.ValidationResult
		penalized bool
	}{
		{"admitted", nil, false, pubsub.ValidationAccept, false},
		{"duplicate from a peer", mempool.ErrDuplicate, false, pubsub.ValidationIgnore, false},
		{"own duplicate", mempool.ErrDuplicate, true, pubsub.ValidationAccept, false},
		{"fee below the relay minimum", fmt.Errorf("%w: pays 1 for 30000 bytes", mempool.ErrFeeTooLow), false, pubsub.ValidationIgnore, false},
		{"pool full", mempool.ErrFull, false, pubsub.ValidationIgnore, false},
		{"conflict", mempool.ErrConflict, false, pubsub.ValidationIgnore, false},
		{"validation not ready", mempool.ErrUnavailable, false, pubsub.ValidationIgnore, false},
		{"resource budget", chain.ErrResourceBudget, false, pubsub.ValidationIgnore, false},
		{"invalid signature", errors.New("chain: invalid kernel authorization"), false, pubsub.ValidationReject, true},
		{"malformed bounds", errors.New("mempool: transaction bounds"), false, pubsub.ValidationReject, true},
	}
	for _, c := range cases {
		got, pen := classifyTxAdmission(c.err, c.local)
		if got != c.want || pen != c.penalized {
			t.Errorf("%s: got (%v, penalize=%v), want (%v, %v)", c.name, got, pen, c.want, c.penalized)
		}
	}
}
