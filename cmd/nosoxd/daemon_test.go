package main

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func freeLoopback(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// runDaemon starts the binary, waits for the peer address line and stops it.
func runDaemon(t *testing.T, bin, data string, extra ...string) string {
	t.Helper()
	args := append([]string{"-data", data, "-rpc", freeLoopback(t), "-p2p", freeLoopback(t), "-network", "testnet", "-testnet-difficulty", "1"}, extra...)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	var out syncBuffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	re := regexp.MustCompile(`/p2p/(12D3Koo\w+)`)
	var id string
	for end := time.Now().Add(30 * time.Second); time.Now().Before(end) && id == ""; time.Sleep(50 * time.Millisecond) {
		if m := re.FindStringSubmatch(out.String()); m != nil {
			id = m[1]
		}
	}
	_ = cmd.Process.Signal(syscall.SIGINT)
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		cancel()
		<-done
	}
	if id == "" {
		t.Fatalf("no peer address in daemon log:\n%s", out.String())
	}
	return id
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// A restarted daemon keeps its libp2p identity (so published /p2p/<id> seeds
// stay valid), and the identity key stays private.
func TestRestartKeepsPeerID(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the daemon")
	}
	bin := filepath.Join(t.TempDir(), "nosoxd")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Env = append(os.Environ(), "GOFLAGS=")
	if o, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, o)
	}
	data := filepath.Join(t.TempDir(), "node")
	first := runDaemon(t, bin, data)
	second := runDaemon(t, bin, data)
	if first != second {
		t.Fatalf("peer ID changed across restart: %s then %s", first, second)
	}
	other := runDaemon(t, bin, filepath.Join(t.TempDir(), "other"))
	if other == first {
		t.Fatal("two data directories share a peer ID")
	}
	matches, _ := filepath.Glob(filepath.Join(data, "*identity*"))
	if len(matches) == 0 {
		t.Fatal("no identity key in the data directory")
	}
	for _, m := range matches {
		if fi, err := os.Stat(m); err != nil || fi.Mode().Perm()&0o077 != 0 {
			t.Fatalf("identity key %s not private: %v %v", m, fi, err)
		}
	}
}

type fakeGate struct {
	peers  atomic.Int64
	synced atomic.Bool
}

func (f *fakeGate) PeerCount() int { return int(f.peers.Load()) }
func (f *fakeGate) Synced() bool   { return f.synced.Load() }

func TestMinerGateFollowsPeersAndSync(t *testing.T) {
	g := &fakeGate{}
	gate := minerGate(g)
	if gate() {
		t.Fatal("open with no peers")
	}
	g.peers.Store(1) // a peer that is ahead of us: still not synced
	if gate() {
		t.Fatal("open while a peer has more work")
	}
	g.synced.Store(true)
	if !gate() {
		t.Fatal("closed although synced")
	}
	g.synced.Store(false) // later: the node falls behind again
	if gate() {
		t.Fatal("gate is one-shot: it stayed open after the node fell behind")
	}
	g.peers.Store(0)
	g.synced.Store(true)
	if gate() {
		t.Fatal("open after losing every peer")
	}
}

// Behind a loopback reverse proxy that forwards its public Host, every request
// used to be refused (403) because the allowlist had no flag.
func TestRPCAllowedHostsFlag(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the daemon")
	}
	bin := filepath.Join(t.TempDir(), "nosoxd")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Env = append(os.Environ(), "GOFLAGS=")
	if o, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, o)
	}
	status := func(extra []string, host string) int {
		rpcAddr := freeLoopback(t)
		args := append([]string{"-data", t.TempDir(), "-rpc", rpcAddr, "-p2p", freeLoopback(t), "-network", "testnet", "-testnet-difficulty", "1"}, extra...)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		cmd := exec.CommandContext(ctx, bin, args...)
		var out syncBuffer
		cmd.Stdout, cmd.Stderr = &out, &out
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() { cancel(); _ = cmd.Wait() }()
		for end := time.Now().Add(30 * time.Second); time.Now().Before(end); time.Sleep(100 * time.Millisecond) {
			req, _ := http.NewRequest("POST", "http://"+rpcAddr+"/", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"getblockcount"}`))
			req.Header.Set("Content-Type", "application/json")
			req.Host = host
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				continue
			}
			resp.Body.Close()
			return resp.StatusCode
		}
		t.Fatalf("RPC never answered:\n%s", out.String())
		return 0
	}
	if got := status(nil, "proxy.example"); got != http.StatusForbidden {
		t.Fatalf("unlisted Host got %d, want 403", got)
	}
	if got := status([]string{"-rpc-allowed-hosts", "proxy.example"}, "proxy.example"); got == http.StatusForbidden {
		t.Fatal("-rpc-allowed-hosts did not admit the listed Host")
	}
}
