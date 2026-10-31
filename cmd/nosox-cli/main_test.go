package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCallRPCSendsTokenFromEnvironmentOnly(t *testing.T) {
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		w.Write([]byte(`{"jsonrpc":"2.0","result":{"height":3},"id":1}`))
	}))
	defer srv.Close()
	t.Setenv(tokenEnv, "env-token")
	out := callRPC(srv.URL, "tip", nil)
	if auth != "Bearer env-token" {
		t.Fatalf("Authorization = %q", auth)
	}
	if m, ok := out.(map[string]any); !ok || m["result"] == nil {
		t.Fatalf("result: %v", out)
	}
	t.Setenv(tokenEnv, "")
	callRPC(srv.URL, "tip", nil)
	if auth != "" {
		t.Fatalf("empty token still sent: %q", auth)
	}
}

func TestUsageNeverAsksForATokenArgument(t *testing.T) {
	// The token is accepted from the environment only.
	r, w, _ := os.Pipe()
	old := os.Stderr
	os.Stderr = w
	usage()
	w.Close()
	os.Stderr = old
	buf := make([]byte, 8192)
	n, _ := r.Read(buf)
	text := string(buf[:n])
	if !strings.Contains(text, tokenEnv) {
		t.Fatal("usage does not document the environment variable")
	}
	for _, bad := range []string{"--token", "-token", "<token>", "rpc-token"} {
		if strings.Contains(text, bad) {
			t.Fatalf("usage mentions a token argument %q", bad)
		}
	}
}

func TestReadPassphraseFromPipe(t *testing.T) {
	for in, want := range map[string]string{"hunter2\n": "hunter2", "with space\r\n": "with space", "nonewline": "nonewline", "first\nsecond\n": "first"} {
		r, w, _ := os.Pipe()
		w.WriteString(in)
		w.Close()
		old := os.Stdin
		os.Stdin = r
		got := readPassphraseNonTTY()
		os.Stdin = old
		if got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}

func TestSlateArgFromFile(t *testing.T) {
	p := t.TempDir() + "/s.txt"
	os.WriteFile(p, []byte("SLATEPACK2.abc\n"), 0o600)
	if got := slateArg("@" + p); strings.TrimSpace(got) != "SLATEPACK2.abc" {
		t.Fatalf("%q", got)
	}
	if slateArg("SLATEPACK2.x") != "SLATEPACK2.x" {
		t.Fatal("literal changed")
	}
}

func TestSanitizeStripsTerminalControl(t *testing.T) {
	in := "bad\x1b[2J\x1b]0;pwned\x07 text‮gnp.exe \x00\r\n\u0085end"
	got := sanitize(in)
	for _, r := range got {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == 0x202e || r == 0x2028 {
			t.Fatalf("control character %U survived: %q", r, got)
		}
	}
	if !strings.Contains(got, "text") || !strings.Contains(got, "end") {
		t.Fatalf("printable text lost: %q", got)
	}
	if long := sanitize(strings.Repeat("a", 5000)); len(long) > 400 {
		t.Fatalf("not capped: %d", len(long))
	}
	if ml := sanitizeMultiline("{\n  \"a\": \"x\x1b[31my\"\n}"); strings.ContainsRune(ml, 0x1b) || !strings.Contains(ml, "\n") {
		t.Fatalf("multiline: %q", ml)
	}
}

func TestCallRPCSanitizesNodeErrorMessages(t *testing.T) {
	if os.Getenv("SANITIZE_CHILD") == "1" {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"jsonrpc":"2.0","error":{"code":-32010,"message":"\u001b[2Jfake \u001b]0;title\u0007"},"id":1}`))
		}))
		defer srv.Close()
		callRPC(srv.URL, "tip", nil)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestCallRPCSanitizesNodeErrorMessages")
	cmd.Env = append(os.Environ(), "SANITIZE_CHILD=1")
	out, _ := cmd.CombinedOutput()
	if strings.ContainsRune(string(out), 0x1b) || strings.ContainsRune(string(out), 7) {
		t.Fatalf("escape sequence reached the terminal: %q", out)
	}
	if !strings.Contains(string(out), "fake") {
		t.Fatalf("message lost: %q", out)
	}
}

func TestStripYes(t *testing.T) {
	assumeYes = false
	got := stripYes([]string{"nosox-cli", "wallet", "--yes", "pay", "-y"})
	if !assumeYes || strings.Join(got, " ") != "nosox-cli wallet pay" {
		t.Fatalf("%v %v", got, assumeYes)
	}
	assumeYes = false
}

// `wallet new` must refuse an existing wallet and weak passphrases, and print
// the unauthenticated-slate warning where slates are produced.
func TestWalletNewRefusesOverwriteAndWeakPassphrase(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the CLI")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "nosox-cli")
	if o, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, o)
	}
	run := func(pass string, args ...string) (string, error) {
		c := exec.Command(bin, args...)
		c.Stdin = strings.NewReader(pass + "\n")
		o, err := c.CombinedOutput()
		return string(o), err
	}
	w := filepath.Join(dir, "w.json")
	if o, err := run("short", "wallet", "new", w); err == nil || !strings.Contains(o, "at least") {
		t.Fatalf("weak passphrase: %v %s", err, o)
	}
	if _, err := os.Stat(w); err == nil {
		t.Fatal("wallet created with a weak passphrase")
	}
	if o, err := run("a long enough passphrase", "wallet", "new", w); err != nil {
		t.Fatalf("new: %v %s", err, o)
	}
	before, _ := os.ReadFile(w)
	if o, err := run("another long passphrase", "wallet", "new", w); err == nil || !strings.Contains(o, "already exists") {
		t.Fatalf("second new: %v %s", err, o)
	}
	if after, _ := os.ReadFile(w); string(after) != string(before) {
		t.Fatal("wallet file was overwritten")
	}
}

func TestIsLoopbackDecidesTheFakeConfirmationWarning(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:7780": true, "localhost:7780": true, "http://127.0.0.1:7780": true, "[::1]:7780": true, "https://localhost/rpc": true,
		"example.com:7780": false, "https://node.example.org": false, "192.168.1.5:7780": false, "http://127.0.0.1.evil.com:7780": false,
	} {
		if got := isLoopback(addr); got != want {
			t.Errorf("isLoopback(%q) = %v, want %v", addr, got, want)
		}
	}
}

func TestSlateFileIsBounded(t *testing.T) {
	p := filepath.Join(t.TempDir(), "big.slate")
	if err := os.WriteFile(p, make([]byte, maxSlateFile+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("NOSOX_TEST_SLATE_CHILD") == "1" {
		slateArg("@" + p) // check() exits non-zero
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestSlateFileIsBounded")
	cmd.Env = append(os.Environ(), "NOSOX_TEST_SLATE_CHILD=1")
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "larger than") {
		t.Fatalf("an oversized slate file was read: %v %s", err, out)
	}
}
