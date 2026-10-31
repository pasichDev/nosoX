package rpc

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/pasichDev/noso-go/v2/chain"
	v2crypto "github.com/pasichDev/noso-go/v2/crypto"
	"github.com/pasichDev/noso-go/v2/mempool"
	"github.com/pasichDev/noso-go/v2/types"
	"github.com/pasichDev/noso-go/v2/wallet"
)

func (s *Service) hasUTXO(resp *jrpcResp, params []interface{}) {
	if s.Chain == nil {
		resp.Error = &jrpcErr{Code: CodeUnavailable, Message: "chain not configured"}
		return
	}
	if len(params) != 1 {
		resp.Error = &jrpcErr{Code: CodeInvalidParams, Message: "expected [commitmentHex]"}
		return
	}
	str, ok := params[0].(string)
	raw, err := hex.DecodeString(str)
	var commit types.Commitment
	if !ok || err != nil || len(raw) != len(commit) {
		resp.Error = &jrpcErr{Code: CodeInvalidParams, Message: "commitment must be 66 hex characters"}
		return
	}
	copy(commit[:], raw)
	if !v2crypto.ValidPublicPoint(commit) {
		resp.Error = &jrpcErr{Code: CodeInvalidParams, Message: "commitment is not a valid curve point"}
		return
	}
	tip, ok := s.Chain.Tip()
	if !ok {
		resp.Error = &jrpcErr{Code: CodeUnavailable, Message: "chain has no tip"}
		return
	}
	out := map[string]any{"present": false, "tip": tip.Height}
	// One indexed lookup in the chain's own UTXO set: no scan, no extra index.
	if o, height, found := s.Chain.UTXOByCommit(commit); found {
		if hash, ok := s.Chain.BlockHash(height); ok {
			out["present"] = true
			out["features"] = uint8(o.Features)
			out["height"] = height
			out["block_hash"] = hash.String()
			out["mature"] = true
			out["matures_at"] = uint64(0)
			if o.Features == types.OutputFeaturesCoinbase {
				// Spendable by a block at height >= created + CoinbaseLock; the
				// next block is tip+1.
				at := height + types.CoinbaseLock
				out["matures_at"] = at
				out["mature"] = tip.Height+1 >= at
			}
			if height > tip.Height {
				out["tip"] = height // the chain advanced between the two lookups
			}
		}
	}
	resp.Result = out
}

func (s *Service) submitTransaction(resp *jrpcResp, params []interface{}) {
	if s.Mempool == nil {
		resp.Error = &jrpcErr{Code: CodeUnavailable, Message: "mempool not configured"}
		return
	}
	if len(params) != 1 {
		resp.Error = &jrpcErr{Code: CodeInvalidParams, Message: "expected [base64Transaction]"}
		return
	}
	str, ok := params[0].(string)
	if !ok || len(str) == 0 || len(str) > base64.StdEncoding.EncodedLen(wallet.MaxEncodedTxBytes) {
		resp.Error = &jrpcErr{Code: CodeInvalidParams, Message: "transaction must be a base64 string within the size limit"}
		return
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(str)
	if err != nil {
		resp.Error = &jrpcErr{Code: CodeInvalidParams, Message: "transaction is not canonical base64"}
		return
	}
	tx, err := wallet.DecodeTx(raw)
	if err != nil {
		resp.Error = &jrpcErr{Code: CodeInvalidParams, Message: clip(err.Error())}
		return
	}
	// Admission goes through the pool's chain validation (NewValidated).
	id, err := s.Mempool.Add(tx)
	duplicate := false
	switch {
	case err == nil:
	case errors.Is(err, mempool.ErrDuplicate):
		// Idempotent retry. Re-validate against the current tip, then re-gossip:
		// the first broadcast may have failed.
		if verr := s.Mempool.Validate(tx); verr != nil {
			resp.Error = s.txError(verr)
			return
		}
		duplicate = true
	default:
		resp.Error = s.txError(err)
		return
	}
	out := map[string]any{"accepted": true, "duplicate": duplicate, "txid": hex.EncodeToString(id[:]), "broadcast": false}
	if s.BroadcastTx != nil {
		if err := s.BroadcastTx(tx); err != nil {
			s.init()
			s.Logf("rpc: broadcast %x: %v", id[:8], err)
			out["broadcast_error"] = "broadcast failed; the transaction is in the mempool, retry to re-gossip"
		} else {
			out["broadcast"] = true
		}
	}
	resp.Result = out
}

// txError separates a definitive rejection (the transaction is invalid; the
// validator's reason is returned, clipped) from a transient refusal (pool full,
// resource budget, validation unavailable) which the wallet must retry rather
// than treat as final.
func (s *Service) txError(err error) *jrpcErr {
	msg := err.Error()
	if errors.Is(err, mempool.ErrFeeTooLow) {
		// A relay-policy rejection, not a transient one: retrying the same
		// transaction cannot succeed. The message carries the fee paid and the
		// minimum required.
		return &jrpcErr{Code: CodeTxRejected, Message: clip("fee too low for relay (policy): " + strings.TrimPrefix(msg, "mempool: fee below minimum relay rate: ") + "; sign a new payment with a higher fee")}
	}
	if errors.Is(err, mempool.ErrConflict) || errors.Is(err, mempool.ErrKernelDup) || errors.Is(err, mempool.ErrReplaceFee) {
		// The pool holds a competing transaction. The submitted one is not
		// invalid and may still be mined (from another node or after the pool
		// changes), so the wallet must not treat this as a final rejection.
		return &jrpcErr{Code: CodeTxPolicy, Message: clip("not admitted by relay policy (a conflicting transaction is pending): " + msg + "; it may still be mined, retry later")}
	}
	if errors.Is(err, chain.ErrResourceBudget) || strings.HasPrefix(msg, "mempool: full") || strings.Contains(msg, "unavailable") {
		return &jrpcErr{Code: CodeTxRetry, Message: "transaction not admitted right now; retry later"}
	}
	return &jrpcErr{Code: CodeTxRejected, Message: clip(msg)}
}

func clip(s string) string {
	if len(s) > 200 {
		return s[:200]
	}
	return s
}
