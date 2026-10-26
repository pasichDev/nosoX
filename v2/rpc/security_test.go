package rpc

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestHeightRejectsInvalidNumbers(t *testing.T) {
	for _, v := range []any{float64(-1), float64(1.5), 1e30, "-1"} {
		if _, err := HeightFromParam(v); err == nil {
			t.Errorf("accepted invalid height %v", v)
		}
	}
	if h, e := HeightFromParam(json.Number("18446744073709551615")); e != nil || h != ^uint64(0) {
		t.Errorf("exact height: %d %v", h, e)
	}
}
func TestRPCRejectsTrailingJSON(t *testing.T) {
	r := post(t, (&Service{}).HTTPHandler(), `{"jsonrpc":"2.0","method":"version","id":1} {}`, "")
	defer r.Body.Close()
	var resp jrpcResp
	_ = json.NewDecoder(r.Body).Decode(&resp)
	if resp.Error == nil {
		t.Fatal("accepted trailing JSON")
	}
}
func TestRPCRejectsOversizedBody(t *testing.T) {
	r := post(t, (&Service{}).HTTPHandler(), `{"jsonrpc":"2.0","method":"version","params":["`+strings.Repeat("a", 1<<20)+`"],"id":1}`, "")
	defer r.Body.Close()
	var resp jrpcResp
	_ = json.NewDecoder(r.Body).Decode(&resp)
	if resp.Error == nil {
		t.Fatal("accepted oversized request")
	}
}
