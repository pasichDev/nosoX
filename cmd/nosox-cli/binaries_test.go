package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestRealBinariesFullPayment builds nosoxd and nosox-cli, runs the daemon on
// loopback in a temp dir with a bearer token, mines past coinbase maturity, and
// drives wallet new / import-coinbase / sync / pay / receive / finalize / sync
// entirely through the CLI, including a second hop (bob -> carol).
//
// It uses the daemon's real testnet genesis (difficulty 256), so it needs about
// 3-5 minutes of CPU on 8 cores to mine the ~60 blocks coinbase maturity needs.
// Skipped under -short.
func TestRealBinariesFullPayment(t *testing.T) {
	if testing.Short() {
		t.Skip("slow: builds binaries and mines ~62 blocks at the daemon's genesis difficulty")
	}
	work := t.TempDir()
	build := func(out, pkg string) string {
		bin := filepath.Join(work, out)
		cmd := exec.Command("go", "build", "-o", bin, pkg)
		cmd.Env = append(os.Environ(), "GOFLAGS=")
		if o, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("go build %s: %v\n%s", pkg, err, o)
		}
		return bin
	}
	daemon := build("nosoxd", "../nosoxd")
	cli := build("nosox-cli", ".")

	rpcAddr, p2pAddr := freeAddr(t), freeAddr(t)
	const token = "binaries-test-token-0123456789abcdef-xyz"
	data := filepath.Join(work, "node")
	var logBuf bytes.Buffer
	dctx, dcancel := context.WithCancel(context.Background())
	d := exec.CommandContext(dctx, daemon, "-data", data, "-rpc", rpcAddr, "-p2p", p2pAddr, "-network", "testnet", "-solo-mine")
	d.Env = append(os.Environ(), tokenEnv+"="+token)
	d.Stdout, d.Stderr = &logBuf, &logBuf
	if err := d.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- d.Wait() }()
	defer func() {
		_ = d.Process.Signal(syscall.SIGTERM)
		select {
		case <-exited:
		case <-time.After(15 * time.Second):
			dcancel()
			<-exited
		}
		dcancel()
		if t.Failed() {
			t.Logf("nosoxd log:\n%s", tail(logBuf.String(), 4000))
		}
	}()
	waitFor(t, 60*time.Second, "daemon health", func() bool {
		resp, err := http.Get("http://" + rpcAddr + "/health")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == 200
	})

	// run executes the CLI with the passphrase on stdin; env controls the token.
	const pass = "binaries test passphrase"
	run := func(withToken bool, pass string, args ...string) (string, string, error) {
		c := exec.Command(cli, args...)
		c.Stdin = strings.NewReader(pass + "\n")
		c.Env = append(os.Environ(), tokenEnv+"=", confirmationsEnv+"=1")
		if withToken {
			c.Env = append(os.Environ(), tokenEnv+"="+token, confirmationsEnv+"=1")
		}
		var so, se bytes.Buffer
		c.Stdout, c.Stderr = &so, &se
		err := c.Run()
		return so.String(), se.String(), err
	}
	must := func(pass string, args ...string) string {
		t.Helper()
		so, se, err := run(true, pass, args...)
		if err != nil {
			t.Fatalf("nosox-cli %v: %v\nstdout: %s\nstderr: %s", args[:2], err, tail(so, 600), tail(se, 600))
		}
		return so
	}
	tipOf := func() (height uint64, pending int) {
		var env struct {
			Result struct {
				Height  uint64 `json:"height"`
				Pending int    `json:"pending"`
			} `json:"result"`
		}
		if err := json.Unmarshal([]byte(must("", "tip", rpcAddr)), &env); err != nil {
			t.Fatal(err)
		}
		return env.Result.Height, env.Result.Pending
	}

	// Token handling: mining control is restricted, tip is public.
	if _, se, err := run(false, "", "mine", "start", rpcAddr, "1", "x"); err == nil || !strings.Contains(strings.ToLower(se+fmt.Sprint(err)), "not authorized") {
		t.Fatalf("mine start without a token should be refused, got err=%v stderr=%q", err, se)
	}
	if _, _, err := run(false, "", "tip", rpcAddr); err != nil {
		t.Fatalf("public method without token: %v", err)
	}
	threads := runtime.NumCPU()
	if threads > 8 {
		threads = 8
	}
	must("", "mine", "start", rpcAddr, fmt.Sprint(threads), "binaries")

	// Wallets.
	alice, bob, carol := filepath.Join(work, "alice.json"), filepath.Join(work, "bob.json"), filepath.Join(work, "carol.json")
	for _, w := range []string{alice, bob, carol} {
		must(pass, "wallet", "new", w)
	}
	if _, _, err := run(true, "wrong passphrase!", "wallet", "balance", alice); err == nil {
		t.Fatal("wrong passphrase accepted")
	}

	// Mine past maturity of the first coinbase: spendable by block >= 61.
	deadline := time.Now().Add(9 * time.Minute)
	for {
		h, _ := tipOf()
		if h >= 62 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("chain only reached height %d in time", h)
		}
		time.Sleep(time.Second)
	}

	// Without a token the wallet cannot even query outputs.
	must(pass, "wallet", "import-coinbase", alice, filepath.Join(data, "coinbases.json"))
	if _, se, err := run(false, pass, "wallet", "sync", alice, rpcAddr); err == nil || !strings.Contains(strings.ToLower(se), "not authorized") {
		t.Fatalf("sync without token: err=%v stderr=%q", err, se)
	}
	must(pass, "wallet", "sync", alice, rpcAddr)
	var bal struct {
		Spendable, Immature, Locked, Pending uint64
		Synced                               bool
	}
	if err := json.Unmarshal([]byte(must(pass, "wallet", "balance", alice)), &bal); err != nil {
		t.Fatal(err)
	}
	if bal.Spendable == 0 || bal.Immature == 0 || !bal.Synced {
		t.Fatalf("alice balance after sync: %+v", bal)
	}

	// alice -> bob.
	const amount1, fee1 = "1500000000", "100000"
	slate1 := lastLine(must(pass, "wallet", "pay", alice, rpcAddr, amount1, fee1, "binaries test"))
	resp1 := lastLine(must(pass, "wallet", "receive", bob, slate1, rpcAddr))
	fin := must(pass, "wallet", "finalize", alice, resp1, rpcAddr)
	if !strings.Contains(fin, "TxHash") {
		t.Fatalf("finalize output: %s", fin)
	}
	waitFor(t, 6*time.Minute, "payment 1 mined", func() bool { _, p := tipOf(); return p == 0 })
	must(pass, "wallet", "sync", bob, rpcAddr)
	if err := json.Unmarshal([]byte(must(pass, "wallet", "balance", bob)), &bal); err != nil {
		t.Fatal(err)
	}
	if bal.Spendable != 1_500_000_000 || bal.Pending != 0 {
		t.Fatalf("bob balance: %+v", bal)
	}

	// bob -> carol, spending the received output.
	slate2 := lastLine(must(pass, "wallet", "pay", bob, rpcAddr, "500000000", "50000"))
	resp2 := lastLine(must(pass, "wallet", "receive", carol, slate2, rpcAddr))
	must(pass, "wallet", "finalize", bob, resp2, rpcAddr)
	// Finalizing again resubmits the identical transaction.
	again := must(pass, "wallet", "finalize", bob, resp2, rpcAddr)
	if !strings.Contains(again, `"Resubmitted": true`) {
		t.Fatalf("second finalize: %s", again)
	}
	waitFor(t, 6*time.Minute, "payment 2 mined", func() bool { _, p := tipOf(); return p == 0 })
	must(pass, "wallet", "sync", carol, rpcAddr)
	if err := json.Unmarshal([]byte(must(pass, "wallet", "balance", carol)), &bal); err != nil {
		t.Fatal(err)
	}
	if bal.Spendable != 500_000_000 {
		t.Fatalf("carol balance: %+v", bal)
	}
	must(pass, "wallet", "sync", bob, rpcAddr)
	if err := json.Unmarshal([]byte(must(pass, "wallet", "balance", bob)), &bal); err != nil {
		t.Fatal(err)
	}
	if bal.Spendable != 1_500_000_000-500_000_000-50_000 {
		t.Fatalf("bob after onward payment: %+v", bal)
	}
	must("", "mine", "stop", rpcAddr)
}

func freeAddr(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func waitFor(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	end := time.Now().Add(d)
	for !cond() {
		if time.Now().After(end) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

func tail(s string, n int) string {
	if len(s) > n {
		return "..." + s[len(s)-n:]
	}
	return s
}
