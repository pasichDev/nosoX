package main

import (
	"strings"
	"testing"
)

const goodToken = "0123456789abcdef0123456789abcdef" // 32 bytes

func TestRPCBindAuthentication(t *testing.T) {
	for _, addr := range []string{":7780", "0.0.0.0:7780", "[::]:7780", "localhost.attacker:7780", "localhost:7780"} {
		if validateRPCConfig(addr, "", true) == nil {
			t.Errorf("unauth bind accepted: %s", addr)
		}
	}
	for _, addr := range []string{"127.0.0.1:7780", "[::1]:7780"} {
		if e := validateRPCConfig(addr, "", false); e != nil {
			t.Error(e)
		}
	}
	if e := validateRPCConfig(":7780", goodToken, true); e != nil {
		t.Fatal(e)
	}
}

// M4: a bearer token must not cross the network in clear text.
func TestNonLoopbackRPCRequiresTLS(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:7780", ":7780", "192.0.2.10:7780"} {
		err := validateRPCConfig(addr, goodToken, false)
		if err == nil || !strings.Contains(err.Error(), "TLS") {
			t.Errorf("%s without TLS: %v", addr, err)
		}
	}
	if err := validateRPCConfig("127.0.0.1:7780", goodToken, false); err != nil {
		t.Fatalf("loopback without TLS must stay possible: %v", err)
	}
}

// M3: the token comes from the environment and must be long enough.
func TestRPCTokenFromEnv(t *testing.T) {
	env := func(v string) func(string) string {
		return func(k string) string {
			if k != rpcTokenEnv {
				t.Fatalf("unexpected variable %s", k)
			}
			return v
		}
	}
	if tok, err := rpcTokenFromEnv(env("")); err != nil || tok != "" {
		t.Fatalf("unset: %q %v", tok, err)
	}
	if tok, err := rpcTokenFromEnv(env(goodToken)); err != nil || tok != goodToken {
		t.Fatalf("good: %q %v", tok, err)
	}
	for name, v := range map[string]string{
		"short":      "secret",
		"31 bytes":   goodToken[:31],
		"whitespace": goodToken + " x",
		"newline":    goodToken + "\n",
		"non-ASCII":  goodToken + "é",
	} {
		if _, err := rpcTokenFromEnv(env(v)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// L4: a taken port is an error before the server starts, not a log line.
func TestRPCBindFailureIsFatal(t *testing.T) {
	first, _, err := rpcListener("127.0.0.1:0", "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, _, err := rpcListener(first.Addr().String(), "", ""); err == nil {
		t.Fatal("second bind on a taken port succeeded")
	}
	if _, _, err := rpcListener("127.0.0.1:0", "/nonexistent/cert.pem", "/nonexistent/key.pem"); err == nil {
		t.Fatal("unusable TLS certificate accepted")
	}
}

func TestP2PRespectsBindHost(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:7781", "[::1]:7781"} {
		addrs, e := p2pListenAddrs(addr)
		if e != nil {
			t.Fatal(e)
		}
		for _, s := range addrs {
			if strings.Contains(s, "0.0.0.0") {
				t.Fatalf("loopback exposed all interfaces: %s", s)
			}
		}
	}
	for _, addr := range []string{"127.0.0.1:70000", "bad", "host:7781"} {
		if _, e := p2pListenAddrs(addr); e == nil {
			t.Errorf("bad address accepted: %s", addr)
		}
	}
}
