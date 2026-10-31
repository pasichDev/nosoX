package p2p

// Compact binary wire format.
//
// Every limit below is derived from the consensus limits in types
// (MaxBlockBodyBytes, MaxBlockInputs, ...), never chosen independently. Counts
// and lengths are checked against those limits BEFORE any slice is allocated, so
// the memory a decoder can be made to use is bounded by the input length, which
// is bounded by the wire limit, which is bounded by consensus. JSON was dropped
// because `{"Kernels":[{},{},...]}` made a 15 MiB payload allocate 2.4 GiB.
//
//	block = header(169) | nIn u8 | in*(feat u8, commit 33)
//	        | nOut u8 | out*(feat u8, commit 33, proofLen u16, proof)
//	        | nKer u8 | ker*(feat u8, fee u64, lock u64, excess 33, sigLen u8, sig)
//	tx    = the same without the header.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/pasichDev/noso-go/v2/chain"
	"github.com/pasichDev/noso-go/v2/types"
)

const (
	headerWireBytes = 4 + 4 + 8 + 8 + 32 + 32 + 32 + 33 + 8 + 8 // 169
	// bodyWireOverhead is the three item counts. Every item's wire size is below
	// the 128/192-byte per-item charge in chain.BodyResourceBytes, so a body that
	// passes that check is at most MaxBlockBodyBytes on the wire.
	bodyWireOverhead = 3

	maxTxWireBytes    = bodyWireOverhead + types.MaxBlockBodyBytes
	maxBlockWireBytes = headerWireBytes + maxTxWireBytes

	// A gossipsub RPC carries a message plus control data; four blocks of room.
	maxGossipRPCBytes = 4 * maxBlockWireBytes

	// A sync response holds at most syncBatchMax blocks, each with a u32 length.
	syncBatchMax      = 64
	maxSyncRespBytes  = 16 + syncBatchMax*(4+maxBlockWireBytes)
	maxLocatorEntries = 64
	maxSyncReqBytes   = 2 + 16 + maxLocatorEntries*32
	maxStatusBytes    = 128
	maxWorkBytes      = 40 // cumulative work is < 2^320 for any realistic chain
	maxRespErrBytes   = 64
)

var errWire = errors.New("p2p: malformed message")

type wbuf struct{ b []byte }

func (w *wbuf) u8(v uint8)   { w.b = append(w.b, v) }
func (w *wbuf) u16(v uint16) { w.b = binary.BigEndian.AppendUint16(w.b, v) }
func (w *wbuf) u32(v uint32) { w.b = binary.BigEndian.AppendUint32(w.b, v) }
func (w *wbuf) u64(v uint64) { w.b = binary.BigEndian.AppendUint64(w.b, v) }
func (w *wbuf) raw(p []byte) { w.b = append(w.b, p...) }

type rbuf struct {
	b   []byte
	err error
}

func (r *rbuf) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || n > len(r.b) {
		r.err = errWire
		return nil
	}
	out := r.b[:n:n]
	r.b = r.b[n:]
	return out
}
func (r *rbuf) u8() uint8 {
	if p := r.take(1); p != nil {
		return p[0]
	}
	return 0
}
func (r *rbuf) u16() uint16 {
	if p := r.take(2); p != nil {
		return binary.BigEndian.Uint16(p)
	}
	return 0
}
func (r *rbuf) u32() uint32 {
	if p := r.take(4); p != nil {
		return binary.BigEndian.Uint32(p)
	}
	return 0
}
func (r *rbuf) u64() uint64 {
	if p := r.take(8); p != nil {
		return binary.BigEndian.Uint64(p)
	}
	return 0
}
func (r *rbuf) fill(dst []byte) { copy(dst, r.take(len(dst))) }

func putHeader(w *wbuf, h *types.BlockHeader) {
	w.u32(h.Version)
	w.u32(h.NetworkMagic)
	w.u64(h.Height)
	w.u64(uint64(h.Timestamp))
	w.raw(h.PrevHash[:])
	w.raw(h.OutputRoot[:])
	w.raw(h.KernelRoot[:])
	w.raw(h.TotalKernelOffset[:])
	w.u64(h.Difficulty)
	w.u64(h.Nonce)
}

func getHeader(r *rbuf) (h types.BlockHeader) {
	h.Version = r.u32()
	h.NetworkMagic = r.u32()
	h.Height = r.u64()
	h.Timestamp = int64(r.u64())
	r.fill(h.PrevHash[:])
	r.fill(h.OutputRoot[:])
	r.fill(h.KernelRoot[:])
	r.fill(h.TotalKernelOffset[:])
	h.Difficulty = r.u64()
	h.Nonce = r.u64()
	return h
}

func putBody(w *wbuf, in []types.Input, out []types.Output, ker []types.Kernel) error {
	if len(in) > types.MaxBlockInputs || len(out) > types.MaxBlockOutputs || len(ker) > types.MaxBlockKernels {
		return errors.New("p2p: body item limit")
	}
	w.u8(uint8(len(in)))
	for i := range in {
		w.u8(uint8(in[i].Features))
		w.raw(in[i].Commit[:])
	}
	w.u8(uint8(len(out)))
	for i := range out {
		if len(out[i].RangeProof) > types.MaxRangeProofBytes {
			return errors.New("p2p: range proof limit")
		}
		w.u8(uint8(out[i].Features))
		w.raw(out[i].Commit[:])
		w.u16(uint16(len(out[i].RangeProof)))
		w.raw(out[i].RangeProof)
	}
	w.u8(uint8(len(ker)))
	for i := range ker {
		if len(ker[i].ExcessSig) > 65 {
			return errors.New("p2p: kernel signature limit")
		}
		w.u8(uint8(ker[i].Features))
		w.u64(ker[i].Fee)
		w.u64(ker[i].LockHeight)
		w.raw(ker[i].Excess[:])
		w.u8(uint8(len(ker[i].ExcessSig)))
		w.raw(ker[i].ExcessSig)
	}
	return nil
}

func getBody(r *rbuf) (in []types.Input, out []types.Output, ker []types.Kernel) {
	n := int(r.u8())
	if n > types.MaxBlockInputs {
		r.err = errWire
		return
	}
	if n > 0 {
		in = make([]types.Input, n)
	}
	for i := 0; i < n && r.err == nil; i++ {
		in[i].Features = types.OutputFeatures(r.u8())
		r.fill(in[i].Commit[:])
	}
	n = int(r.u8())
	if n > types.MaxBlockOutputs {
		r.err = errWire
		return
	}
	if n > 0 {
		out = make([]types.Output, n)
	}
	for i := 0; i < n && r.err == nil; i++ {
		out[i].Features = types.OutputFeatures(r.u8())
		r.fill(out[i].Commit[:])
		pl := int(r.u16())
		if pl > types.MaxRangeProofBytes {
			r.err = errWire
			return
		}
		if p := r.take(pl); p != nil && pl > 0 {
			out[i].RangeProof = append([]byte(nil), p...)
		}
	}
	n = int(r.u8())
	if n > types.MaxBlockKernels {
		r.err = errWire
		return
	}
	if n > 0 {
		ker = make([]types.Kernel, n)
	}
	for i := 0; i < n && r.err == nil; i++ {
		ker[i].Features = types.KernelFeatures(r.u8())
		ker[i].Fee = r.u64()
		ker[i].LockHeight = r.u64()
		r.fill(ker[i].Excess[:])
		sl := int(r.u8())
		if sl > 65 {
			r.err = errWire
			return
		}
		if p := r.take(sl); p != nil && sl > 0 {
			ker[i].ExcessSig = append([]byte(nil), p...)
		}
	}
	return
}

func appendBlock(w *wbuf, b *types.Block) error {
	if b == nil {
		return errors.New("p2p: nil block")
	}
	putHeader(w, &b.Header)
	return putBody(w, b.Inputs, b.Outputs, b.Kernels)
}

func readBlock(r *rbuf) (*types.Block, error) {
	b := &types.Block{Header: getHeader(r)}
	b.Inputs, b.Outputs, b.Kernels = getBody(r)
	if r.err != nil {
		return nil, r.err
	}
	if err := checkBody(b.Inputs, b.Outputs, b.Kernels); err != nil {
		return nil, err
	}
	return b, nil
}

func encodeBlockMsg(b *types.Block) ([]byte, error) {
	w := &wbuf{b: make([]byte, 0, 1024)}
	if err := appendBlock(w, b); err != nil {
		return nil, err
	}
	return w.b, nil
}

func decodeBlockMsg(raw []byte) (*types.Block, error) {
	if len(raw) < headerWireBytes+bodyWireOverhead || len(raw) > maxBlockWireBytes {
		return nil, errors.New("p2p: payload size")
	}
	r := &rbuf{b: raw}
	b, err := readBlock(r)
	if err != nil {
		return nil, err
	}
	if len(r.b) != 0 {
		return nil, errors.New("p2p: trailing payload")
	}
	return b, nil
}

func encodeTxMsg(tx *types.Transaction) ([]byte, error) {
	if tx == nil {
		return nil, errors.New("p2p: nil transaction")
	}
	w := &wbuf{b: make([]byte, 0, 1024)}
	if err := putBody(w, tx.Inputs, tx.Outputs, tx.Kernels); err != nil {
		return nil, err
	}
	return w.b, nil
}

func decodeTxMsg(raw []byte) (*types.Transaction, error) {
	if len(raw) < bodyWireOverhead || len(raw) > maxTxWireBytes {
		return nil, errors.New("p2p: payload size")
	}
	r := &rbuf{b: raw}
	tx := &types.Transaction{}
	tx.Inputs, tx.Outputs, tx.Kernels = getBody(r)
	if r.err != nil {
		return nil, r.err
	}
	if len(r.b) != 0 {
		return nil, errors.New("p2p: trailing payload")
	}
	if err := checkBody(tx.Inputs, tx.Outputs, tx.Kernels); err != nil {
		return nil, err
	}
	return tx, nil
}

// checkBody applies the native consensus envelope before admission. Genesis
// allocations are trusted local inputs, never imported through gossip/sync.
func checkBody(in []types.Input, out []types.Output, k []types.Kernel) error {
	_, err := chain.BodyResourceBytes(&types.Block{Header: types.BlockHeader{Height: 1}, Inputs: in, Outputs: out, Kernels: k})
	if err != nil {
		return fmt.Errorf("p2p: native body envelope: %w", err)
	}
	return nil
}

// ---- hello status ------------------------------------------------------

// Status is what the hello handshake exchanges. Peers are compared by
// cumulative work, never by height.
type Status struct {
	Version      uint32
	NetworkMagic uint32
	Height       uint64
	TipHash      types.Hash
	// TotalWork is the cumulative work of the peer's canonical chain.
	TotalWork *big.Int
}

func encodeStatus(st Status) []byte {
	w := &wbuf{}
	w.u32(st.Version)
	w.u32(st.NetworkMagic)
	w.u64(st.Height)
	w.raw(st.TipHash[:])
	var work []byte
	if st.TotalWork != nil && st.TotalWork.Sign() > 0 {
		work = st.TotalWork.Bytes()
	}
	if len(work) > maxWorkBytes {
		work = bytes.Repeat([]byte{0xff}, maxWorkBytes)
	}
	w.u8(uint8(len(work)))
	w.raw(work)
	return w.b
}

func decodeStatus(raw []byte) (Status, error) {
	var st Status
	if len(raw) > maxStatusBytes {
		return st, errors.New("p2p: payload size")
	}
	r := &rbuf{b: raw}
	st.Version = r.u32()
	st.NetworkMagic = r.u32()
	st.Height = r.u64()
	r.fill(st.TipHash[:])
	wl := int(r.u8())
	if wl > maxWorkBytes {
		return st, errWire
	}
	st.TotalWork = new(big.Int).SetBytes(r.take(wl))
	if r.err != nil {
		return st, r.err
	}
	if len(r.b) != 0 {
		return st, errors.New("p2p: trailing payload")
	}
	return st, nil
}

// ---- sync requests -----------------------------------------------------

const (
	reqBlocks  uint8 = 1 // From..To inclusive, at most syncBatchMax blocks
	reqLocator uint8 = 2 // find the highest locator hash on the responder's canonical chain
)

// GetBlocksReq asks for a range of blocks. Both ends inclusive.
type GetBlocksReq struct {
	From uint64
	To   uint64
}

type syncReq struct {
	Kind    uint8
	Blocks  GetBlocksReq
	Locator []types.Hash
}

func encodeSyncReq(q syncReq) []byte {
	w := &wbuf{}
	w.u8(q.Kind)
	switch q.Kind {
	case reqBlocks:
		w.u64(q.Blocks.From)
		w.u64(q.Blocks.To)
	case reqLocator:
		loc := q.Locator
		if len(loc) > maxLocatorEntries {
			loc = loc[:maxLocatorEntries]
		}
		w.u8(uint8(len(loc)))
		for i := range loc {
			w.raw(loc[i][:])
		}
	}
	return w.b
}

func decodeSyncReq(raw []byte) (syncReq, error) {
	var q syncReq
	if len(raw) > maxSyncReqBytes {
		return q, errors.New("p2p: payload size")
	}
	r := &rbuf{b: raw}
	q.Kind = r.u8()
	switch q.Kind {
	case reqBlocks:
		q.Blocks.From = r.u64()
		q.Blocks.To = r.u64()
	case reqLocator:
		n := int(r.u8())
		if n > maxLocatorEntries {
			return q, errWire
		}
		for i := 0; i < n && r.err == nil; i++ {
			var h types.Hash
			r.fill(h[:])
			q.Locator = append(q.Locator, h)
		}
	default:
		return q, errWire
	}
	if r.err != nil {
		return q, r.err
	}
	if len(r.b) != 0 {
		return q, errors.New("p2p: trailing payload")
	}
	return q, nil
}

// GetBlocksResp is the response to a block-range request.
type GetBlocksResp struct {
	Blocks []*types.Block
	Err    string // non-empty means the responder failed (e.g. out of range)
}

const (
	respOK          uint8 = 0
	respRateLimited uint8 = 1
	respError       uint8 = 2
)

func encodeBlocksResp(resp *GetBlocksResp) ([]byte, error) {
	w := &wbuf{}
	switch {
	case resp.Err == ErrRateLimited.Error():
		w.u8(respRateLimited)
		return w.b, nil
	case resp.Err != "":
		msg := resp.Err
		if len(msg) > maxRespErrBytes {
			msg = msg[:maxRespErrBytes]
		}
		w.u8(respError)
		w.u8(uint8(len(msg)))
		w.raw([]byte(msg))
		return w.b, nil
	}
	if len(resp.Blocks) > syncBatchMax {
		return nil, errors.New("p2p: too many blocks")
	}
	w.u8(respOK)
	w.u8(uint8(len(resp.Blocks)))
	for _, b := range resp.Blocks {
		inner := &wbuf{}
		if err := appendBlock(inner, b); err != nil {
			return nil, err
		}
		w.u32(uint32(len(inner.b)))
		w.raw(inner.b)
	}
	return w.b, nil
}

func decodeBlocksResp(raw []byte) (*GetBlocksResp, error) {
	if len(raw) > maxSyncRespBytes {
		return nil, errors.New("p2p: payload size")
	}
	r := &rbuf{b: raw}
	resp := &GetBlocksResp{}
	switch code := r.u8(); code {
	case respRateLimited:
		resp.Err = ErrRateLimited.Error()
	case respError:
		n := int(r.u8())
		if n > maxRespErrBytes {
			return nil, errWire
		}
		resp.Err = string(r.take(n))
		if resp.Err == "" {
			resp.Err = "error"
		}
	case respOK:
		n := int(r.u8())
		if n > syncBatchMax {
			return nil, errWire
		}
		for i := 0; i < n && r.err == nil; i++ {
			l := int(r.u32())
			if l > maxBlockWireBytes {
				return nil, errWire
			}
			inner := &rbuf{b: r.take(l)}
			if r.err != nil {
				break
			}
			b, err := readBlock(inner)
			if err != nil {
				return nil, err
			}
			if len(inner.b) != 0 {
				return nil, errors.New("p2p: trailing payload")
			}
			resp.Blocks = append(resp.Blocks, b)
		}
	default:
		return nil, errWire
	}
	if r.err != nil {
		return nil, r.err
	}
	if len(r.b) != 0 {
		return nil, errors.New("p2p: trailing payload")
	}
	return resp, nil
}

// locatorResp is the answer to a reqLocator: the canonical height of the first
// (highest) locator entry the responder has on its chain. The requester checks
// the height against its own locator, so a lying responder can only pick an
// earlier ancestor (more blocks to fetch) and is caught on anything else.
type locatorResp struct {
	Found  bool
	Height uint64
}

func encodeLocatorResp(l locatorResp) []byte {
	w := &wbuf{}
	if l.Found {
		w.u8(respOK)
		w.u64(l.Height)
	} else {
		w.u8(respError)
	}
	return w.b
}

func decodeLocatorResp(raw []byte) (locatorResp, error) {
	var l locatorResp
	if len(raw) > 9 {
		return l, errors.New("p2p: payload size")
	}
	r := &rbuf{b: raw}
	switch r.u8() {
	case respOK:
		l.Found, l.Height = true, r.u64()
	case respRateLimited:
		return l, ErrRateLimited
	case respError:
	default:
		return l, errWire
	}
	if r.err != nil {
		return l, r.err
	}
	if len(r.b) != 0 {
		return l, errors.New("p2p: trailing payload")
	}
	return l, nil
}

// ---- framing -----------------------------------------------------------

// writeFrame prepends a 4-byte big-endian length to body and writes both in one
// call.
func writeFrame(w io.Writer, body []byte) error {
	buf := make([]byte, 4, 4+len(body))
	binary.BigEndian.PutUint32(buf, uint32(len(body)))
	_, err := w.Write(append(buf, body...))
	return err
}

// readFrame reads a length-prefixed payload bounded by maxLen bytes. The
// buffer grows only as bytes really arrive, so a peer that announces a large
// frame and then stalls costs nothing.
func readFrame(r io.Reader, maxLen uint32) ([]byte, error) {
	var lp [4]byte
	if _, err := io.ReadFull(r, lp[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lp[:])
	if n > maxLen {
		return nil, io.ErrShortBuffer
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(io.LimitReader(r, int64(n))); err != nil {
		return nil, err
	}
	if buf.Len() != int(n) {
		return nil, io.ErrUnexpectedEOF
	}
	return buf.Bytes(), nil
}
