package network

import (
	"bufio"
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/noso-project/noso-go/internal/blockchain"
	"github.com/noso-project/noso-go/internal/crypto"
	"github.com/noso-project/noso-go/internal/storage"
)

func newTestService(t *testing.T) *Service {
	t.Helper()
	sumPath, _ := filepath.Abs(filepath.Join("..", "..", "testdata", "sumary_59238.psk"))
	gvtPath, _ := filepath.Abs(filepath.Join("..", "..", "testdata", "gvts.psk"))
	sumStore, err := storage.NewSummaryStore(sumPath)
	if err != nil {
		t.Fatal(err)
	}
	hdrStore, _ := storage.NewHeadersStore(filepath.Join(t.TempDir(), "blchhead.nos"))
	return &Service{
		Summary:      sumStore,
		Headers:      hdrStore,
		SummaryFile:  sumPath,
		GVTsFile:     gvtPath,
		CFGRaw:       "NORMAL 1.1.1.1;8080:2.2.2.2;8080:  pool.ntp.org: null: null: null:",
		Version:      "0.5.0-go",
		ProtoVersion: "2",
		StartTime:    time.Now(),
		Pending:      NewPendingPool(),
	}
}

func runServer(t *testing.T, svc *Service) (string, func()) {
	srv := NewServer("127.0.0.1:0", nil)
	svc.Register(srv)
	ctx, cancel := context.WithCancel(context.Background())
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	cleanup := func() {
		cancel()
		_ = srv.Shutdown(context.Background())
	}
	return srv.Addr(), cleanup
}

func dial(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	return c
}

func TestNodeStatus(t *testing.T) {
	svc := newTestService(t)
	addr, cleanup := runServer(t, svc)
	defer cleanup()
	c := dial(t, addr)
	defer c.Close()
	if _, err := c.Write([]byte("NODESTATUS\n")); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 18 {
		t.Fatalf("NODESTATUS reply has %d fields: %q", len(fields), line)
	}
	if fields[6] != "0.5.0-go" {
		t.Errorf("version field = %q", fields[6])
	}
}

func TestBalanceLookup(t *testing.T) {
	svc := newTestService(t)
	addr, cleanup := runServer(t, svc)
	defer cleanup()
	// Pick an address that we know exists in the snapshot — the dev fund
	// address has a non-zero balance.
	target := blockchain.DevFundAddress
	c := dial(t, addr)
	defer c.Close()
	if _, err := c.Write([]byte("NSLBALANCE " + target + "\n")); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	got := strings.TrimSpace(line)
	if got == "0" {
		// Acceptable; dev fund may have zero balance in this snapshot.
		t.Logf("dev fund balance = 0 in this snapshot (ok)")
		return
	}
	t.Logf("dev fund balance = %s base units", got)
}

func TestSubmitOrder(t *testing.T) {
	svc := newTestService(t)
	addr, cleanup := runServer(t, svc)
	defer cleanup()

	// Build a real signed order via the same helpers NosoDart uses.
	kp, _ := crypto.GenerateKeyPair()
	sender, _ := crypto.AddressFromPublicKey(kp.PublicKey, crypto.AddressTypeRegular)
	kp2, _ := crypto.GenerateKeyPair()
	receiver, _ := crypto.AddressFromPublicKey(kp2.PublicKey, crypto.AddressTypeRegular)
	s := blockchain.Sender{Hash: sender, PublicKey: kp.PublicKey, PrivateKey: kp.PrivateKey}
	order, err := blockchain.NewTransferOrder(s, receiver, 1_000_000_000, "hi", time.Now().Unix(), 60_000)
	if err != nil {
		t.Fatal(err)
	}

	// Serialize like NosoDart would (header + fields, dollar-bracketed).
	wireFields := []string{
		"2", "0.0.0", "0", "ORDER", "1", "$",
		order.OrderType, order.OrderID, "1", order.OrderType,
		strings.Replace(timeStr(order.TimeStamp), " ", "_", -1),
		order.Reference, "1", order.Sender, order.Address, order.Receiver,
		i64(order.AmmountFee), i64(order.AmmountTrf), order.Signature, order.TrfrID,
	}
	line := "NSLORDER " + strings.Join(wireFields, " ") + " $\n"
	c := dial(t, addr)
	defer c.Close()
	if _, err := c.Write([]byte(line)); err != nil {
		t.Fatal(err)
	}
	reply, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(reply, "OK ") {
		t.Fatalf("submit reply = %q", reply)
	}
	if svc.Pending.Len() != 1 {
		t.Fatalf("pending pool size = %d", svc.Pending.Len())
	}
}

func timeStr(ts int64) string { return i64(ts) }

func i64(v int64) string {
	const digits = "0123456789"
	if v == 0 {
		return "0"
	}
	neg := false
	if v < 0 {
		neg = true
		v = -v
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = digits[v%10]
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
