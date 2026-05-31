package network

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/noso-project/noso-go/internal/blockchain"
	"github.com/noso-project/noso-go/internal/storage"
	"github.com/noso-project/noso-go/internal/types"
)

// Service bundles everything a TCP handler needs to answer NosoDart
// requests. Build one at node startup and register its handlers on the
// network.Server.
type Service struct {
	Summary       *storage.SummaryStore
	Headers       *storage.HeadersStore
	GVTs          []types.GVT
	CFGRaw        string         // verbatim nosocfg.psk contents
	SummaryFile   string         // path to sumary.psk on disk
	GVTsFile      string         // path to gvts.psk on disk
	Version       string         // e.g. "0.5.0"
	ProtoVersion  string         // PSK protocol version, e.g. "2"
	ListenAddress string         // ip:port string for advertising in NODESTATUS
	StartTime     time.Time      // for uptime reporting
	Pending       *PendingPool   // optional, may be nil
}

// PendingPool is a tiny thread-safe transaction pool. Lives in the network
// package because it's tightly coupled to the wire format; a future block
// builder can promote it.
type PendingPool struct {
	mu      sync.RWMutex
	entries []types.Order
}

// NewPendingPool returns an empty pool.
func NewPendingPool() *PendingPool { return &PendingPool{} }

// Add inserts o, deduping by TrfrID. Returns false if already present.
func (p *PendingPool) Add(o types.Order) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := range p.entries {
		if p.entries[i].TrfrID == o.TrfrID {
			return false
		}
	}
	p.entries = append(p.entries, o)
	sort.SliceStable(p.entries, func(i, j int) bool {
		if p.entries[i].TimeStamp != p.entries[j].TimeStamp {
			return p.entries[i].TimeStamp < p.entries[j].TimeStamp
		}
		if p.entries[i].OrderID != p.entries[j].OrderID {
			return p.entries[i].OrderID < p.entries[j].OrderID
		}
		return p.entries[i].TrxLine < p.entries[j].TrxLine
	})
	return true
}

// Snapshot returns a copy of the current entries.
func (p *PendingPool) Snapshot() []types.Order {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]types.Order, len(p.entries))
	copy(out, p.entries)
	return out
}

// Len returns the pool size.
func (p *PendingPool) Len() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.entries)
}

// Register installs every supported NosoDart command on srv.
func (svc *Service) Register(srv *Server) {
	srv.HandleFunc("NODESTATUS", svc.handleNodeStatus)
	srv.HandleFunc("NSLMNS", svc.handleSeeds)
	srv.HandleFunc("NSLPENDFULL", svc.handlePendingFull)
	srv.HandleFunc("GETZIPSUMARY", svc.handleZipSummary)
	srv.HandleFunc("NSLCFG", svc.handleCFG)
	srv.HandleFunc("NSLGVT", svc.handleGVTBinary)
	srv.HandleFunc("NSLBALANCE", svc.handleBalance)
	srv.HandleFunc("NSLORDER", svc.handleSubmitOrder)
	srv.HandleFunc("NSLCUSTOM", svc.handleSubmitCustom)
}

// handleNodeStatus answers with the space-separated 18-field status string
// NosoDart's `parseDataNode()` expects. Layout (index → meaning):
//
//	0 conn-marker  (Pascal puts something, NosoDart skips)
//	1 connections
//	2 lastblock
//	3 pendings
//	4 delta
//	5 branch (version string suffix)
//	6 version (Pascal node version)
//	7 utcTime
//	8 listen port (signed -1 if not listening)
//	9 (unused by Dart but present in Pascal)
//	10 lastblockhash (first 5 hex chars)
//	11..14 (unused by Dart)
//	15 headershash (first 5 chars)
//	16 (unused)
//	17 sumaryhash (first 5 chars)
//
// We fill in archival defaults for fields that don't apply offline.
func (svc *Service) handleNodeStatus(ctx context.Context, w *bufio.Writer, cmd string, args []string) error {
	tip, _ := svc.Headers.Tip()
	lastBlock := int64(tip.Block)
	lastBlockHash := first5(tip.BlockHash)
	sumHash := first5(tip.SumHash)
	headersHash := first5(tip.SumHash) // archive: no separate computed header hash yet
	pending := 0
	if svc.Pending != nil {
		pending = svc.Pending.Len()
	}
	fields := []string{
		"NOSODATA",                              // 0
		"0",                                     // 1 connections
		strconv.FormatInt(lastBlock, 10),        // 2 lastblock
		strconv.Itoa(pending),                   // 3 pendings
		"0",                                     // 4 delta
		"archive",                               // 5 branch
		svc.Version,                             // 6 version
		strconv.FormatInt(time.Now().Unix(), 10), // 7 utc time
		"8080",                                  // 8 listen port placeholder
		"0",                                     // 9
		lastBlockHash,                           // 10 lastblockhash[:5]
		"null", "0", "0", "0",                   // 11..14 padding
		headersHash,                             // 15 headers[:5]
		"0",                                     // 16
		sumHash,                                 // 17 sumaryhash[:5]
	}
	_, err := fmt.Fprintln(w, strings.Join(fields, " "))
	return err
}

// handleSeeds returns a space-separated seed list. Format expected by
// `parseDataSeeds`: `"seed1 ip;port:address ip;port:address ..."`. We just
// re-emit the seeds from nosocfg if available.
func (svc *Service) handleSeeds(ctx context.Context, w *bufio.Writer, cmd string, args []string) error {
	// "seed1" is the placeholder Dart skips; emit it always.
	out := []string{"seeds"}
	cfg := storage.NosoCFG{Raw: svc.CFGRaw}
	parsed := parseCFGInline(svc.CFGRaw)
	for _, s := range parsed.Seeds {
		// Pascal seeds carry an optional :address suffix used for
		// signature; absent in our archive, so we substitute "null".
		out = append(out, s+":null")
	}
	_ = cfg
	_, err := fmt.Fprintln(w, strings.Join(out, " "))
	return err
}

func parseCFGInline(raw string) *storage.NosoCFG {
	// Avoid importing storage in test code that doesn't have it: use the
	// existing parser via a string-only entry point. NosoCFG fields are
	// populated by storage.LoadNosoCFG; we can replicate the minimal seed
	// section parse here for simplicity.
	cfg := &storage.NosoCFG{Raw: raw}
	sections := strings.Split(strings.TrimSpace(raw), " ")
	if len(sections) > 1 {
		for _, s := range strings.Split(sections[1], ":") {
			if s != "" && s != "null" {
				cfg.Seeds = append(cfg.Seeds, s)
			}
		}
	}
	return cfg
}

// handlePendingFull emits one CSV-on-the-line entry per pending order,
// matching `parseDataPendings` in `utils/data_parser.dart:178-208`.
func (svc *Service) handlePendingFull(ctx context.Context, w *bufio.Writer, cmd string, args []string) error {
	if svc.Pending == nil {
		_, err := fmt.Fprintln(w, "")
		return err
	}
	entries := svc.Pending.Snapshot()
	parts := make([]string, 0, len(entries))
	for _, o := range entries {
		// orderId,?,orderType,sender,receiver,amount,fee,?
		parts = append(parts, strings.Join([]string{
			o.OrderID,
			"0",
			o.OrderType,
			o.Address,
			o.Receiver,
			strconv.FormatInt(o.AmmountTrf, 10),
			strconv.FormatInt(o.AmmountFee, 10),
			"0",
		}, ","))
	}
	_, err := fmt.Fprintln(w, strings.Join(parts, " "))
	return err
}

// handleZipSummary streams a freshly built ZIP of sumary.psk. The Dart
// client locates the inner ZIP via a `PK\x03\x04` byte search and unzips
// from there, so prefixing extra bytes is allowed; we emit ZIP bytes
// directly with no prefix.
func (svc *Service) handleZipSummary(ctx context.Context, w *bufio.Writer, cmd string, args []string) error {
	body, err := os.ReadFile(svc.SummaryFile)
	if err != nil {
		return err
	}
	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	f, err := zw.Create("sumary.psk")
	if err != nil {
		return err
	}
	if _, err := f.Write(body); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	if _, err := w.Write(zbuf.Bytes()); err != nil {
		return err
	}
	// NosoDart reads until EOF on this connection for binary streams,
	// so we flush and close after the write.
	return w.Flush()
}

// handleCFG returns the raw nosocfg.psk contents.
func (svc *Service) handleCFG(ctx context.Context, w *bufio.Writer, cmd string, args []string) error {
	_, err := fmt.Fprintln(w, svc.CFGRaw)
	return err
}

// handleGVTBinary emits the gvts.psk file verbatim. NosoDart skips the
// first 20 bytes of the reply and then reads 105-byte records — see
// `data_parser.dart:264-287`. The 20-byte prefix is a Pascal-side ZIP
// header artifact; we keep parity by prepending 20 zero bytes.
func (svc *Service) handleGVTBinary(ctx context.Context, w *bufio.Writer, cmd string, args []string) error {
	body, err := os.ReadFile(svc.GVTsFile)
	if err != nil {
		return err
	}
	if _, err := w.Write(make([]byte, 20)); err != nil {
		return err
	}
	if _, err := w.Write(body); err != nil {
		return err
	}
	return w.Flush()
}

// handleBalance returns a single balance line. NosoDart calls
// `NSLBALANCE <hash>` and parses the response as a number.
func (svc *Service) handleBalance(ctx context.Context, w *bufio.Writer, cmd string, args []string) error {
	if len(args) < 1 {
		_, err := fmt.Fprintln(w, "0")
		return err
	}
	rec, ok := svc.Summary.Get(args[0])
	if !ok {
		_, err := fmt.Fprintln(w, "0")
		return err
	}
	_, err := fmt.Fprintln(w, strconv.FormatInt(rec.Balance, 10))
	return err
}

// handleSubmitOrder accepts an NSLORDER batch.
func (svc *Service) handleSubmitOrder(ctx context.Context, w *bufio.Writer, cmd string, args []string) error {
	o, err := parseOrderLine(args)
	if err != nil {
		_, _ = fmt.Fprintf(w, "ERROR %v\n", err)
		return nil
	}
	if !blockchain.VerifyOrder(o) {
		_, _ = fmt.Fprintln(w, "ERROR signature invalid")
		return nil
	}
	if svc.Pending == nil {
		svc.Pending = NewPendingPool()
	}
	if !svc.Pending.Add(*o) {
		_, _ = fmt.Fprintln(w, "DUPLICATE")
		return nil
	}
	_, _ = fmt.Fprintln(w, "OK "+o.OrderID)
	return nil
}

// handleSubmitCustom accepts an NSLCUSTOM order. Internally it shares the
// parser with NSLORDER because the wire format is identical.
func (svc *Service) handleSubmitCustom(ctx context.Context, w *bufio.Writer, cmd string, args []string) error {
	return svc.handleSubmitOrder(ctx, w, "NSLORDER", args)
}

// parseOrderLine parses the space-separated, dollar-bracketed wire format
// the Dart client emits. The shape (per `models/order.dart:34-42`):
//
//	<protocol> <appVersion> <utcTime> ORDER <trxLine> $ <orderType>
//	  <orderID> <orderLines> <orderType> <timeStamp> <message>
//	  <trxLine> <sender> <address> <receiver> <amountFee> <amountTrf>
//	  <signature> <trfrID> $
//
// Note that <orderType> appears TWICE — once just after the leading `$` as
// a section marker, and once again in the order body. The trailing `$` is
// a section terminator. We tolerate optional header and section markers
// so the function can also be called with just the 13 order fields.
func parseOrderLine(args []string) (*types.Order, error) {
	// Trim any trailing "$" markers — they're section terminators.
	for len(args) > 0 && args[len(args)-1] == "$" {
		args = args[:len(args)-1]
	}
	// Trim leading "$" markers.
	for len(args) > 0 && args[0] == "$" {
		args = args[1:]
	}
	// Skip optional NosoDart prefix: protocol version, app version, utc time,
	// the literal "ORDER", trxLine, and the section-opening "$".
	if len(args) >= 5 && strings.EqualFold(args[3], "ORDER") {
		args = args[5:]
	}
	for len(args) > 0 && args[0] == "$" {
		args = args[1:]
	}
	// Drop the orderType prefix marker if present. Known types are
	// TRFR / CUSTOM / SNDGVT / PROJCT — we sniff with a small allowlist
	// so that a malformed leading token surfaces as a parse error rather
	// than silently shifting all field positions.
	if len(args) > 0 && isKnownOrderType(args[0]) && len(args) >= 14 {
		args = args[1:]
	}
	// Now expect exactly 13 fields: orderID orderLines orderType timestamp
	// reference trxLine sender address receiver fee amount signature trfrID.
	if len(args) < 13 {
		return nil, fmt.Errorf("network: order line has %d fields, want >= 13", len(args))
	}
	o := &types.Order{}
	o.OrderID = args[0]
	n, err := strconv.Atoi(args[1])
	if err != nil {
		return nil, fmt.Errorf("orderLines: %w", err)
	}
	o.OrderLines = int32(n)
	o.OrderType = args[2]
	ts, err := strconv.ParseInt(args[3], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("timestamp: %w", err)
	}
	o.TimeStamp = ts
	o.Reference = args[4]
	tl, err := strconv.Atoi(args[5])
	if err != nil {
		return nil, fmt.Errorf("trxLine: %w", err)
	}
	o.TrxLine = int32(tl)
	o.Sender = args[6]
	o.Address = args[7]
	o.Receiver = args[8]
	if fee, err := strconv.ParseInt(args[9], 10, 64); err == nil {
		o.AmmountFee = fee
	} else {
		return nil, fmt.Errorf("fee: %w", err)
	}
	if amt, err := strconv.ParseInt(args[10], 10, 64); err == nil {
		o.AmmountTrf = amt
	} else {
		return nil, fmt.Errorf("amount: %w", err)
	}
	o.Signature = args[11]
	o.TrfrID = args[12]
	return o, nil
}

func isKnownOrderType(s string) bool {
	switch s {
	case types.OrderTypeTransfer, types.OrderTypeCustom, types.OrderTypeSendGVT, types.OrderTypeProjectPayment:
		return true
	}
	return false
}

func first5(s string) string {
	if len(s) >= 5 {
		return s[:5]
	}
	if s == "" {
		return "00000"
	}
	return s
}
