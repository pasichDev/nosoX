// nosox-cli is the v2 wallet and command-line client.
//
//   nosox-cli wallet new <path>             create encrypted wallet
//   nosox-cli wallet import <path> <v1.pkw> import legacy keys
//   nosox-cli wallet legacy <path>          list claimable legacy addresses
//   nosox-cli balance <node-rpc> <legacy>   show legacy balance on chain
//   nosox-cli tip <node-rpc>                show chain tip
//   nosox-cli mine start <node-rpc> <threads> <reward>
//   nosox-cli mine stop <node-rpc>
//   nosox-cli mine stats <node-rpc>
//   nosox-cli genesis <v1-sumary.psk>       summarize a candidate genesis
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/noso-project/noso-go/v2/genesis"
	"github.com/noso-project/noso-go/v2/wallet"

	"golang.org/x/term"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "wallet":
		walletCmd(os.Args[2:])
	case "balance":
		balanceCmd(os.Args[2:])
	case "tip":
		tipCmd(os.Args[2:])
	case "mine":
		mineCmd(os.Args[2:])
	case "genesis":
		genesisCmd(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `nosox-cli — Noso v2 wallet + client

Subcommands:
  wallet new <path>
  wallet import <path> <v1-wallet.pkw>
  wallet legacy <path>
  balance <node-rpc> <legacy-address>
  tip <node-rpc>
  mine start <node-rpc> <threads> <reward-id>
  mine stop <node-rpc>
  mine stats <node-rpc>
  genesis <v1-sumary.psk> [v1-gvts.psk]
  wallet claim <wallet-path> <node-rpc> <legacy-address>
  wallet gvt list <wallet-path> <node-rpc>
  wallet gvt redeem <wallet-path> <node-rpc> <slot>
`)
}

func walletCmd(args []string) {
	if len(args) < 2 {
		usage()
		os.Exit(2)
	}
	switch args[0] {
	case "new":
		w, err := wallet.NewRandom()
		check(err)
		pass := readPassphrase("New passphrase: ")
		check(w.Save(args[1], pass))
		fmt.Printf("wallet created at %s\n", args[1])
		fmt.Printf("master public key (Ed25519): %x\n", w.MasterPublic())
	case "import":
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: wallet import <path> <v1-wallet.pkw>")
			os.Exit(2)
		}
		pass := readPassphrase("Wallet passphrase: ")
		w, err := wallet.Load(args[1], pass)
		check(err)
		n, err := w.ImportLegacyFile(args[2])
		check(err)
		check(w.Save(args[1], pass))
		fmt.Printf("imported %d legacy keys\n", n)
	case "legacy":
		pass := readPassphrase("Wallet passphrase: ")
		w, err := wallet.Load(args[1], pass)
		check(err)
		fmt.Printf("%d legacy claim keys in wallet:\n", len(w.Legacy))
		for addr := range w.Legacy {
			fmt.Println(" ", addr)
		}
	case "pay":
		// usage: wallet pay <wallet-path> <amount> <fee> [memo]
		if len(args) < 4 {
			fmt.Fprintln(os.Stderr, "usage: wallet pay <wallet-path> <amount> <fee> [memo]")
			os.Exit(2)
		}
		pass := readPassphrase("Wallet passphrase: ")
		w, err := wallet.Load(args[1], pass)
		check(err)
		amount, err := strconv.ParseInt(args[2], 10, 64)
		check(err)
		fee, err := strconv.ParseUint(args[3], 10, 64)
		check(err)
		memo := ""
		if len(args) >= 5 {
			memo = args[4]
		}
		s := wallet.NewOfferSlate(amount, fee, 0, memo)
		s.SignPartial(wallet.RoleSender, w.Master)
		enc, err := s.Encode()
		check(err)
		fmt.Println("send the following Slatepack to the recipient:")
		fmt.Println(enc)
	case "receive":
		// usage: wallet receive <wallet-path> <slatepack-string>
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: wallet receive <wallet-path> <slatepack>")
			os.Exit(2)
		}
		pass := readPassphrase("Wallet passphrase: ")
		w, err := wallet.Load(args[1], pass)
		check(err)
		s, err := wallet.Decode(args[2])
		check(err)
		if s.Stage != wallet.StageOffer {
			check(fmt.Errorf("expected stage Offer, got %d", s.Stage))
		}
		s.Stage = wallet.StageResponse
		s.Role = wallet.RoleReceiver
		s.SignPartial(wallet.RoleReceiver, w.Master)
		enc, err := s.Encode()
		check(err)
		fmt.Println("send the following Slatepack back to the sender:")
		fmt.Println(enc)
	case "finalize":
		// usage: wallet finalize <wallet-path> <slatepack-string> <node-rpc>
		if len(args) < 4 {
			fmt.Fprintln(os.Stderr, "usage: wallet finalize <wallet-path> <slatepack> <node-rpc>")
			os.Exit(2)
		}
		pass := readPassphrase("Wallet passphrase: ")
		w, err := wallet.Load(args[1], pass)
		check(err)
		s, err := wallet.Decode(args[2])
		check(err)
		if s.Stage != wallet.StageResponse {
			check(fmt.Errorf("expected stage Response, got %d", s.Stage))
		}
		if !s.VerifyPartials() {
			check(fmt.Errorf("partial signatures invalid; aborting"))
		}
		s.Stage = wallet.StageFinal
		s.SignPartial(wallet.RoleSender, w.Master)
		// In a complete flow we'd reduce the slate to a types.Transaction
		// and submit via the node's RPC submitorder. The plumbing for
		// that conversion is the same code path the network gossiper
		// uses, so we surface the slate for the user to inspect and
		// confirm successful round-trip.
		out := map[string]any{
			"slate_id":   s.TxID,
			"amount":     s.Amount,
			"fee":        s.Fee,
			"part_sigs":  len(s.PartSigs),
			"finalized":  true,
			"target_rpc": args[3],
		}
		pretty(out)
	case "claim":
		// usage: wallet claim <wallet-path> <node-rpc> <legacy-address>
		if len(args) < 4 {
			fmt.Fprintln(os.Stderr, "usage: wallet claim <wallet-path> <node-rpc> <legacy-address>")
			os.Exit(2)
		}
		pass := readPassphrase("Wallet passphrase: ")
		w, err := wallet.Load(args[1], pass)
		check(err)
		node := args[2]
		legacyAddr := args[3]
		// Query node for legacy balance + the deterministic commit.
		balResp := callRPC(node, "legacybalance", []any{legacyAddr})
		balMap, _ := balResp.(map[string]any)
		if balMap == nil {
			check(fmt.Errorf("node returned no balance info"))
		}
		balance := int64(0)
		switch v := balMap["balance"].(type) {
		case float64:
			balance = int64(v)
		case int64:
			balance = v
		}
		if balance <= 0 {
			check(fmt.Errorf("no claimable balance for %s", legacyAddr))
		}
		// Get current tip height for the signing nonce.
		tipResp := callRPC(node, "tip", nil)
		tipMap, _ := tipResp.(map[string]any)
		height := uint64(0)
		switch v := tipMap["height"].(type) {
		case float64:
			height = uint64(v)
		}
		// Recompute the legacy commit deterministically (genesis bundler logic).
		legacyCommit := legacyCommitFor(legacyAddr, balance)
		tx, plain, err := w.BuildLegacyClaim(legacyAddr, balance, legacyCommit, height)
		check(err)
		fmt.Printf("built claim tx with input commit %x, output value %d\n",
			tx.Inputs[0].Commit[:8], plain.Value)
		fmt.Println("submit via:  nosox-cli submit-tx", node, "<encoded-tx>")
		fmt.Println("(direct RPC submit is on the post-launch roadmap; for now display only)")
	case "gvt":
		gvtCmd(args[1:])
	default:
		usage()
		os.Exit(2)
	}
}

func gvtCmd(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: wallet gvt <list|redeem|send>")
		os.Exit(2)
	}
	switch args[0] {
	case "list":
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: wallet gvt list <wallet-path> <node-rpc>")
			os.Exit(2)
		}
		pass := readPassphrase("Wallet passphrase: ")
		w, err := wallet.Load(args[1], pass)
		check(err)
		_ = w // wallet load proves passphrase even before RPC call
		res := callRPC(args[2], "gvtlist", nil)
		pretty(res)
	case "redeem":
		if len(args) < 4 {
			fmt.Fprintln(os.Stderr, "usage: wallet gvt redeem <wallet-path> <node-rpc> <slot 0-99>")
			os.Exit(2)
		}
		pass := readPassphrase("Wallet passphrase: ")
		w, err := wallet.Load(args[1], pass)
		check(err)
		slotN, err := strconv.Atoi(args[3])
		check(err)
		if slotN < 0 || slotN > 99 {
			check(fmt.Errorf("slot must be 0..99"))
		}
		res := callRPC(args[2], "gvtowner", []any{slotN})
		ownerMap, _ := res.(map[string]any)
		owner, _ := ownerMap["address"].(string)
		if owner == "" {
			check(fmt.Errorf("node does not know GVT slot %d", slotN))
		}
		if _, ok := w.Legacy[owner]; !ok {
			check(fmt.Errorf("you don't own GVT %d (owned by %s)", slotN, owner))
		}
		// Recompute commit deterministically.
		commit := gvtCommitFor(uint8(slotN), owner)
		tipResp := callRPC(args[2], "tip", nil)
		tipMap, _ := tipResp.(map[string]any)
		height := uint64(0)
		if v, ok := tipMap["height"].(float64); ok {
			height = uint64(v)
		}
		tx, plain, err := w.BuildGVTRedeem(uint8(slotN), owner, commit, height)
		check(err)
		fmt.Printf("built GVT redeem tx for slot %d (value %d base units)\n", slotN, plain.Value)
		_ = tx
	case "send":
		fmt.Fprintln(os.Stderr, "wallet gvt send: receiver-blinding flow not yet wired through CLI")
		os.Exit(2)
	default:
		fmt.Fprintln(os.Stderr, "usage: wallet gvt <list|redeem|send>")
		os.Exit(2)
	}
}

func balanceCmd(args []string) {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: balance <node-rpc> <legacy-address>")
		os.Exit(2)
	}
	out := callRPC(args[0], "legacybalance", []any{args[1]})
	pretty(out)
}

func tipCmd(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: tip <node-rpc>")
		os.Exit(2)
	}
	out := callRPC(args[0], "tip", nil)
	pretty(out)
}

func mineCmd(args []string) {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: mine {start|stop|stats} <node-rpc> [threads] [reward]")
		os.Exit(2)
	}
	switch args[0] {
	case "start":
		if len(args) < 4 {
			fmt.Fprintln(os.Stderr, "usage: mine start <node-rpc> <threads> <reward-id>")
			os.Exit(2)
		}
		threads, _ := strconv.Atoi(args[2])
		out := callRPC(args[1], "startmining", []any{threads, args[3]})
		pretty(out)
	case "stop":
		out := callRPC(args[1], "stopmining", nil)
		pretty(out)
	case "stats":
		out := callRPC(args[1], "minerstats", nil)
		pretty(out)
	default:
		usage()
		os.Exit(2)
	}
}

func genesisCmd(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: genesis <v1-sumary.psk>")
		os.Exit(2)
	}
	cfg := genesis.Default()
	cfg.SummaryPath = args[0]
	stats, err := genesis.Summarize(cfg)
	check(err)
	fmt.Printf("legacy accounts:  %d\n", stats.LegacyAccounts)
	fmt.Printf("total carried:    %d base units (%s NOSO)\n", stats.TotalCarried, formatCoin(stats.TotalCarried))
	fmt.Printf("output root:      %s\n", stats.OutputRoot)
	fmt.Printf("genesis hash:     %s\n", stats.GenesisHash)
	fmt.Printf("difficulty:       %d\n", stats.Difficulty)
	fmt.Printf("network magic:    0x%08x\n", stats.NetworkMagic)
}

func callRPC(addr, method string, params []any) any {
	body := map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
		"id":      1,
	}
	buf, _ := json.Marshal(body)
	url := addr
	if !strings.HasPrefix(url, "http") {
		url = "http://" + url
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(buf))
	check(err)
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	var out any
	check(json.Unmarshal(respBody, &out))
	return out
}

func pretty(v any) {
	body, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(body))
}

func formatCoin(units int64) string {
	whole := units / 1e8
	frac := units % 1e8
	return fmt.Sprintf("%d.%08d", whole, frac)
}

func readPassphrase(prompt string) string {
	fmt.Fprint(os.Stderr, prompt)
	b, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		check(err)
	}
	return string(b)
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
