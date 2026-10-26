package main

import (
	"strings"
	"testing"
)

func TestRPCBindAuthentication(t *testing.T) {
	for _, addr := range []string{":7780", "0.0.0.0:7780", "[::]:7780", "localhost.attacker:7780", "localhost:7780"} {
		if validateRPCBind(addr, "") == nil {
			t.Errorf("unauth bind accepted: %s", addr)
		}
	}
	for _, addr := range []string{"127.0.0.1:7780", "[::1]:7780"} {
		if e := validateRPCBind(addr, ""); e != nil {
			t.Error(e)
		}
	}
	if e := validateRPCBind(":7780", "secret"); e != nil {
		t.Fatal(e)
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
