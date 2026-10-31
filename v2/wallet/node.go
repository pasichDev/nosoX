package wallet

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pasichDev/noso-go/v2/types"
)

// UTXOInfo is a node's answer about one commitment.
type UTXOInfo struct {
	Present  bool
	Features types.OutputFeatures
	// Mature reports whether the output may be spent in the node's next block.
	Mature bool
	// MaturesAt is the first block height that may spend it (coinbase only; 0 otherwise).
	MaturesAt uint64
	// Height is the creation height when the node could determine it cheaply
	// (only for coinbase outputs still inside the maturity window).
	Height uint64
	// BlockHash is the hash of the block that created the output (hex), when known.
	BlockHash string
	Tip       uint64
}

// ErrRejected wraps a node's explicit refusal of a submitted transaction (as
// opposed to a transport failure, after which the outcome is unknown).
var ErrRejected = errors.New("wallet: node rejected transaction")

// Node is what the wallet needs from a full node. The production
// implementation is RPCNode; tests use an in-process chain adapter.
type Node interface {
	// UTXO reports whether commit is currently unspent and when it matures.
	UTXO(commit types.Commitment) (UTXOInfo, error)
	// BlockHash returns the canonical block hash at height; ok is false when the
	// node has no block at that height (for instance after a reorg).
	BlockHash(height uint64) (hash string, ok bool, err error)
	// NetworkMagic returns the network magic of the chain the node serves.
	NetworkMagic() (uint32, error)
	// Submit offers a signed transaction to the node's mempool. Submitting a
	// transaction the node already has must succeed (idempotent retry).
	Submit(tx *types.Transaction) error
}

// RPCNode talks JSON-RPC to nosoxd.
type RPCNode struct {
	URL    string
	Token  string
	Client *http.Client
}

// JSON-RPC codes the wallet interprets (mirrors v2/rpc).
const (
	rpcCodeInvalidParams = -32602
	rpcCodeNotFound      = -32004
	rpcCodeTxRejected    = -32010
	rpcCodeTxPolicy      = -32013
	rpcCodeBusy          = -32020
	rpcCodeRateLimited   = -32021
)

// maxRPCResponse bounds what the wallet will read from a node.
const maxRPCResponse = 1 << 20

// NewRPCNode builds a client for addr ("host:port" or a URL). Only HTTPS or a
// loopback address is accepted: a node reached over plain http across a network
// is refused, token or not.
func NewRPCNode(addr, token string) (*RPCNode, error) {
	u := addr
	if !strings.Contains(u, "://") {
		u = "http://" + u
	}
	pu, err := url.Parse(u)
	if err != nil || pu.Host == "" || (pu.Scheme != "http" && pu.Scheme != "https") {
		return nil, fmt.Errorf("wallet: bad node address %q", addr)
	}
	if pu.Scheme == "http" && !isLoopbackHost(pu.Hostname()) {
		// Plain http to a remote host exposes the token AND lets anyone on the
		// path forge the answers the wallet treats as chain state.
		return nil, errors.New("wallet: refusing plain http to a non-loopback node; use https")
	}
	return &RPCNode{
		URL:   pu.String(),
		Token: token,
		Client: &http.Client{
			Timeout: 60 * time.Second,
			// Never follow redirects: they could carry the bearer token elsewhere.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func isLoopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

type rpcEnvelope struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// RPCError is a JSON-RPC error object returned by the node.
type RPCError struct {
	Code    int
	Message string
	HTTP    int
}

func (e *RPCError) Error() string {
	return fmt.Sprintf("rpc error %d (http %d): %s", e.Code, e.HTTP, e.Message)
}

// maxThrottleRetries bounds how often a call is repeated after the node says it
// is busy or rate limiting this client (HTTP 429, or 503 with code -32020/-32021).
const maxThrottleRetries = 8

// CallRaw performs one JSON-RPC call and returns the full response body. A
// node that throttles the client is retried a few times with a growing pause.
func (n *RPCNode) CallRaw(method string, params []any) ([]byte, int, error) {
	for attempt := 0; ; attempt++ {
		raw, status, err := n.callOnce(method, params)
		if err != nil || attempt >= maxThrottleRetries || !throttled(raw, status) {
			return raw, status, err
		}
		time.Sleep(time.Duration(attempt+1) * 100 * time.Millisecond)
	}
}

func throttled(raw []byte, status int) bool {
	if status == http.StatusTooManyRequests {
		return true
	}
	if status != http.StatusServiceUnavailable {
		return false
	}
	var env rpcEnvelope
	return json.Unmarshal(raw, &env) == nil && env.Error != nil && (env.Error.Code == rpcCodeBusy || env.Error.Code == rpcCodeRateLimited)
}

func (n *RPCNode) callOnce(method string, params []any) ([]byte, int, error) {
	if params == nil {
		params = []any{}
	}
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": method, "params": params, "id": 1})
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequest(http.MethodPost, n.URL, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if n.Token != "" {
		req.Header.Set("Authorization", "Bearer "+n.Token)
	}
	resp, err := n.Client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxRPCResponse+1))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if len(raw) > maxRPCResponse {
		return nil, resp.StatusCode, errors.New("wallet: node response too large")
	}
	return raw, resp.StatusCode, nil
}

// Call performs one JSON-RPC call and returns its result member.
func (n *RPCNode) Call(method string, params []any) (json.RawMessage, error) {
	raw, status, err := n.CallRaw(method, params)
	if err != nil {
		return nil, err
	}
	var env rpcEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("wallet: node answered http %d with a non-JSON-RPC body", status)
	}
	if env.Error != nil {
		return nil, &RPCError{Code: env.Error.Code, Message: clipNodeText(env.Error.Message), HTTP: status}
	}
	if status != http.StatusOK {
		return nil, &RPCError{Code: 0, Message: "unexpected http status", HTTP: status}
	}
	return env.Result, nil
}

// UTXO implements Node.
func (n *RPCNode) UTXO(c types.Commitment) (UTXOInfo, error) {
	res, err := n.Call("hasutxo", []any{commitHex(c)})
	if err != nil {
		return UTXOInfo{}, err
	}
	var r struct {
		Present   bool   `json:"present"`
		Features  uint8  `json:"features"`
		Mature    bool   `json:"mature"`
		MaturesAt uint64 `json:"matures_at"`
		Height    uint64 `json:"height"`
		BlockHash string `json:"block_hash"`
		Tip       uint64 `json:"tip"`
	}
	dec := json.NewDecoder(bytes.NewReader(res))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return UTXOInfo{}, fmt.Errorf("wallet: bad hasutxo result: %w", err)
	}
	return UTXOInfo{Present: r.Present, Features: types.OutputFeatures(r.Features), Mature: r.Mature, MaturesAt: r.MaturesAt, Height: r.Height, BlockHash: r.BlockHash, Tip: r.Tip}, nil
}

// Submit implements Node. A node-side rejection is returned as ErrRejected
// wrapping the node's message; transport errors are returned unwrapped (the
// outcome is then unknown and the caller must retry with the same transaction).
func (n *RPCNode) Submit(tx *types.Transaction) error {
	raw, err := EncodeTx(tx)
	if err != nil {
		return err
	}
	_, err = n.Call("submittransaction", []any{base64.StdEncoding.EncodeToString(raw)})
	var re *RPCError
	if errors.As(err, &re) && re.Code == rpcCodeTxPolicy {
		// A relay-policy refusal (for example a conflicting transaction is already
		// pending): not a statement that the transaction is invalid.
		return fmt.Errorf("%w: %s", ErrPolicyRefused, re.Message)
	}
	if errors.As(err, &re) && (re.Code == rpcCodeTxRejected || re.Code == rpcCodeInvalidParams) {
		return fmt.Errorf("%w: %s", ErrRejected, re.Message)
	}
	return err
}

// NetworkMagic implements Node using the public genesisinfo method.
func (n *RPCNode) NetworkMagic() (uint32, error) {
	res, err := n.Call("genesisinfo", nil)
	if err != nil {
		return 0, err
	}
	var r struct {
		Network uint32 `json:"network"`
	}
	if err := json.Unmarshal(res, &r); err != nil || r.Network == 0 {
		return 0, errors.New("wallet: bad genesisinfo result")
	}
	return r.Network, nil
}

// BlockHash implements Node using the public getblock method.
func (n *RPCNode) BlockHash(height uint64) (string, bool, error) {
	res, err := n.Call("getblock", []any{height})
	if err != nil {
		var re *RPCError
		if errors.As(err, &re) && re.Code == rpcCodeNotFound {
			return "", false, nil
		}
		return "", false, err
	}
	var r struct {
		Hash string `json:"hash"`
	}
	if err := json.Unmarshal(res, &r); err != nil || len(r.Hash) != 64 {
		return "", false, errors.New("wallet: bad getblock result")
	}
	return r.Hash, true, nil
}

// clipNodeText bounds text supplied by a node before it is embedded in errors.
func clipNodeText(s string) string {
	const max = 200
	r := []rune(s)
	if len(r) > max {
		return string(r[:max]) + "..."
	}
	return s
}
