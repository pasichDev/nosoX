// nosox-cli is the NosoX wallet and command-line client.
//
//	nosox-cli wallet new <path>
//	nosox-cli wallet pay <path> <node-rpc> <amount> <fee> [memo]
//	nosox-cli wallet receive <path> <slate> [node-rpc]
//	nosox-cli wallet finalize <path> <slate> <node-rpc>
//	nosox-cli wallet outputs <path>
//	nosox-cli wallet balance <path>
//	nosox-cli wallet sync <path> <node-rpc> [--accept-tip <height>]
//	nosox-cli wallet consolidate <path> <node-rpc> [fee|default] [rounds]
//	nosox-cli wallet cancel <path> <txid> [--force]
//	nosox-cli wallet cancel-receive <path> <txid>
//	nosox-cli wallet import-coinbase <path> <coinbases.json>
//	nosox-cli tip <node-rpc>
//	nosox-cli mine start <node-rpc> <threads> <reward>
//	nosox-cli mine stop <node-rpc>
//	nosox-cli mine stats <node-rpc>
//
// The RPC bearer token is read from the NOSOX_RPC_TOKEN environment variable
// and is never accepted on the command line. NOSOX_CONFIRMATIONS sets the
// confirmation depth (default 10). --yes skips the interactive confirmation. The wallet passphrase is read
// from the terminal; when stdin is not a terminal a single line is read from it.
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unicode"

	"github.com/pasichDev/nosoX/v2/types"
	"github.com/pasichDev/nosoX/v2/wallet"

	"golang.org/x/term"
)

// tokenEnv names the environment variable holding the RPC bearer token.
const tokenEnv = "NOSOX_RPC_TOKEN"

// confirmationsEnv sets the confirmation depth the wallet requires.
const confirmationsEnv = "NOSOX_CONFIRMATIONS"

// assumeYes is set by --yes: skip the interactive confirmation prompts.
var assumeYes bool

// slateWarning is printed whenever a slate is created or accepted.
const slateWarning = `WARNING: slates are not authenticated or encrypted. Whoever answers a payment offer
receives the payment, and nothing proves afterwards who was paid. Hand slates only
over a channel you trust, and check the recipient out of band. There is no payment proof.`

func main() {
	os.Args = stripYes(os.Args)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "wallet":
		walletCmd(os.Args[2:])
	case "tip":
		tipCmd(os.Args[2:])
	case "mine":
		mineCmd(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func stripYes(args []string) []string {
	out := args[:0:0]
	for _, a := range args {
		if a == "--yes" || a == "-y" {
			assumeYes = true
			continue
		}
		out = append(out, a)
	}
	return out
}

func usage() {
	fmt.Fprintf(os.Stderr, `nosox-cli - NosoX wallet + client

Subcommands:
  wallet new <wallet-path>
  wallet pay <wallet-path> <node-rpc> <amount> <fee|default> [memo]
%s  wallet receive <wallet-path> <slate|@file> [node-rpc]
  wallet finalize <wallet-path> <slate|@file> <node-rpc>
  wallet outputs <wallet-path>
  wallet balance <wallet-path>
  wallet sync <wallet-path> <node-rpc> [--accept-tip <height>]
  wallet consolidate <wallet-path> <node-rpc> [fee|default] [rounds]   (merge up to %d of the smallest outputs per round)
  wallet cancel <wallet-path> <txid> [--force]
  wallet cancel-receive <wallet-path> <txid>   (abandon an unconfirmed incoming payment; its key is kept)
  wallet import-coinbase <wallet-path> <coinbases.json>   (also reads coinbases.json.<ts>.<n> archives beside it)
  tip <node-rpc>
  mine start <node-rpc> <threads> <reward-id>
  mine stop <node-rpc>
  mine stats <node-rpc>

Options:
  --yes   do not ask for confirmation before signing or answering a payment

Environment:
  %s   RPC bearer token (never pass it as an argument)
  %s   blocks an output must be buried under to count as confirmed (default 10)
`, payFeeHelp(), types.MaxBlockInputs, tokenEnv, confirmationsEnv)
}

func argErr(msg string) {
	fmt.Fprintln(os.Stderr, "usage:", msg)
	os.Exit(2)
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
		defer w.Close()
		pass := readNewPassphrase()
		// Create never replaces an existing wallet or state file: a new wallet
		// needs a new path.
		check(w.Create(args[1], pass))
		fmt.Printf("wallet created at %s\n", args[1])
		fmt.Printf("master public key (Ed25519): %x\n", w.MasterPublic())
		fmt.Fprintln(os.Stderr, "There is no recovery phrase: back up the wallet file AND its .outputs state file together, and keep the passphrase.")
	case "pay":
		if len(args) < 5 {
			argErr(payUsage())
		}
		node := newNode(args[2])
		amount, err := strconv.ParseInt(args[3], 10, 64)
		check(err)
		fee := wallet.DefaultFee()
		if args[4] != "default" {
			var err error
			fee, err = strconv.ParseUint(args[4], 10, 64)
			check(err)
		}
		if min := wallet.MinRelayFee(1, 2); fee < min {
			fmt.Fprintf(os.Stderr, "warning: fee %d is below the relay minimum for even a one-input payment (%d); nodes will refuse to relay it\n", fee, min)
		} else if max := wallet.MinRelayFee(types.MaxBlockInputs, 2); fee < max {
			fmt.Fprintf(os.Stderr, "warning: fee %d is enough for a one-input payment but not for one with %d inputs (%d); if the wallet needs that many inputs the node will refuse it. Use \"default\" to be safe\n", fee, types.MaxBlockInputs, max)
		}
		memo := ""
		if len(args) >= 6 {
			memo = args[5]
		}
		describe("PAY", amount, fee, 0, memo, args[2])
		confirm("Prepare this payment? [y/N] ")
		st, closeAll := openStore(args[1])
		defer closeAll()
		s, err := st.Pay(node, wallet.PayParams{Amount: amount, Fee: fee, Memo: memo})
		check(err)
		enc, err := s.Encode()
		check(err)
		fmt.Fprintf(os.Stderr, "payment %x prepared; inputs are locked. Send this slate to the recipient:\n", s.TxID)
		fmt.Fprintln(os.Stderr, slateWarning)
		fmt.Println(enc)
	case "receive":
		if len(args) < 3 {
			argErr("wallet receive <wallet-path> <slate|@file> [node-rpc]")
		}
		offer, err := wallet.Decode(slateArg(args[2]))
		check(err)
		describe("RECEIVE", offer.Amount, offer.Fee, offer.LockHeight, offer.Memo, "")
		confirm("Answer this offer? [y/N] ")
		st, closeAll := openStore(args[1])
		defer closeAll()
		if len(args) >= 4 {
			// Pin (or check) the wallet's network against the node.
			magic, err := newNode(args[3]).NetworkMagic()
			check(err)
			check(st.SetNetwork(magic))
		}
		resp, err := st.Receive(offer)
		check(err)
		enc, err := resp.Encode()
		check(err)
		fmt.Fprintf(os.Stderr, "received %d units (pending until confirmed). Send this slate back to the sender:\n", resp.Amount)
		fmt.Fprintln(os.Stderr, slateWarning)
		fmt.Println(enc)
	case "finalize":
		if len(args) < 4 {
			argErr("wallet finalize <wallet-path> <slate|@file> <node-rpc>")
		}
		resp, err := wallet.Decode(slateArg(args[2]))
		check(err)
		node := newNode(args[3])
		describe("FINALIZE (sign and submit)", resp.Amount, resp.Fee, resp.LockHeight, resp.Memo, args[3])
		confirm("Sign and submit this transaction? [y/N] ")
		st, closeAll := openStore(args[1])
		defer closeAll()
		res, err := st.Finalize(node, resp)
		if res != nil {
			pretty(res)
		}
		check(err)
	case "outputs":
		st, closeAll := openStore(args[1])
		defer closeAll()
		pretty(st.Outputs())
	case "balance":
		st, closeAll := openStore(args[1])
		defer closeAll()
		pretty(st.Balance())
	case "sync":
		if len(args) < 3 {
			argErr("wallet sync <wallet-path> <node-rpc> [--accept-tip <height>]")
		}
		var opt wallet.SyncOptions
		switch {
		case len(args) == 3:
		case len(args) == 5 && args[3] == "--accept-tip":
			h, err := strconv.ParseUint(args[4], 10, 64)
			check(err)
			opt.AcceptTip = h
		default:
			argErr("wallet sync <wallet-path> <node-rpc> [--accept-tip <height>]")
		}
		node := newNode(args[2])
		st, closeAll := openStore(args[1])
		defer closeAll()
		rep, err := st.SyncWith(node, opt)
		check(err)
		pretty(rep)
		fmt.Fprintln(os.Stderr, wallet.SyncTrustNotice)
		if !isLoopback(args[2]) {
			fmt.Fprintf(os.Stderr, "WARNING: %s is not on this machine. It can report fake confirmations, and its tip is only sanity-checked, never proven.\n", sanitize(args[2]))
		}
	case "consolidate":
		if len(args) < 4 || len(args) > 6 {
			argErr("wallet consolidate <wallet-path> <node-rpc> [fee|default] [rounds]")
		}
		node := newNode(args[2])
		fee := wallet.DefaultFee()
		if len(args) >= 5 && args[4] != "default" {
			var err error
			fee, err = strconv.ParseUint(args[4], 10, 64)
			check(err)
		}
		rounds := 1
		if len(args) == 6 {
			r, err := strconv.Atoi(args[5])
			check(err)
			if r < 1 || r > 20 {
				check(errors.New("rounds must be between 1 and 20"))
			}
			rounds = r
		}
		describe("CONSOLIDATE (merge your smallest outputs into one, paying yourself)", 0, fee, 0, "consolidate", args[2])
		confirm("Merge outputs? [y/N] ")
		st, closeAll := openStore(args[1])
		defer closeAll()
		for i := 1; i <= rounds; i++ {
			res, err := st.Consolidate(node, fee)
			if res != nil {
				pretty(res)
			}
			if err != nil {
				if i > 1 {
					fmt.Fprintf(os.Stderr, "stopped after %d round(s)\n", i-1)
				}
				check(err)
			}
		}
		fmt.Fprintln(os.Stderr, "Submitted. The merged outputs become spendable after the confirmation depth; run `wallet sync` after the next blocks.")
	case "cancel":
		if len(args) < 3 {
			argErr("wallet cancel <wallet-path> <txid> [--force]")
		}
		force := false
		for _, a := range args[3:] {
			if a != "--force" {
				argErr("wallet cancel <wallet-path> <txid> [--force]")
			}
			force = true
		}
		txid := strings.ToLower(args[2])
		if b, err := hex.DecodeString(txid); err != nil || len(b) != 16 {
			check(errors.New("txid must be 32 hex characters"))
		}
		if force {
			fmt.Fprintln(os.Stderr, "WARNING: --force releases the inputs of a payment that is already signed. The transaction may still be mined (from another node's pool, or later): if it is, and you pay again, the recipient is paid twice. Do this only if it can never be mined, for example the node rejected it as invalid. A node that merely did not admit it right now (relay policy, pool full) is NOT a reason.")
			confirm("Release the inputs anyway? [y/N] ")
		}
		st, closeAll := openStore(args[1])
		defer closeAll()
		check(st.Cancel(txid, force))
		fmt.Printf("payment %s cancelled\n", txid)
	case "cancel-receive":
		if len(args) != 3 {
			argErr("wallet cancel-receive <wallet-path> <txid>")
		}
		txid := strings.ToLower(args[2])
		if b, err := hex.DecodeString(txid); err != nil || len(b) != 16 {
			check(errors.New("txid must be 32 hex characters"))
		}
		st, closeAll := openStore(args[1])
		defer closeAll()
		check(st.CancelReceive(txid))
		fmt.Printf("incoming payment %s abandoned; its key is kept encrypted in the wallet in case the sender still completes it\n", txid)
	case "import-coinbase":
		if len(args) < 3 {
			argErr("wallet import-coinbase <wallet-path> <coinbases.json>")
		}
		st, closeAll := openStore(args[1])
		defer closeAll()
		rep, err := st.ImportCoinbase(args[2])
		check(err)
		pretty(rep)
	default:
		usage()
		os.Exit(2)
	}
}

// payUsage is the `wallet pay` usage line, with the relay minimum fee so a
// fee that no node would relay is not typed blind.
func payUsage() string {
	return "wallet pay <wallet-path> <node-rpc> <amount> <fee|default> [memo]\n" + payFeeHelp()
}

func payFeeHelp() string {
	return fmt.Sprintf("      relay minimum fee: %d base units for a 1-input payment, %d for %d inputs (nodes refuse lower fees);\n"+
		"      \"default\" = %d, enough for any payment this wallet builds\n",
		wallet.MinRelayFee(1, 2), wallet.MinRelayFee(types.MaxBlockInputs, 2), types.MaxBlockInputs, wallet.DefaultFee())
}

// openStore prompts for the passphrase once, unlocks the keystore (which
// authenticates the passphrase) and opens the encrypted output state.
func openStore(path string) (*wallet.Store, func()) {
	pass := readPassphrase("Wallet passphrase: ")
	w, err := wallet.Load(path, pass)
	check(err)
	if w.Legacy {
		// Version 1 keystores used a weak key derivation; rewrite as version 2.
		if err := w.Upgrade(path, pass); err != nil {
			w.Close()
			check(fmt.Errorf("upgrading the keystore: %w", err))
		}
		fmt.Fprintf(os.Stderr, "keystore upgraded to the current format (stronger key derivation). The old file was kept as %s%s: it holds everything the old keystore held (including any imported legacy keys the new format does not carry) under the OLD weak encryption. Keep it until you have checked what you need, then delete it. There is no command to change the passphrase of an existing wallet; a new passphrase means a new wallet.\n", path, wallet.UpgradeBackupSuffix)
	}
	st, err := wallet.OpenStore(path, pass, w.MasterPublic())
	if err != nil {
		w.Close()
		check(err)
	}
	if v := os.Getenv(confirmationsEnv); v != "" {
		n, perr := strconv.Atoi(v)
		if perr == nil {
			perr = st.SetMinConfirmations(n)
		}
		if perr != nil {
			st.Close()
			w.Close()
			check(fmt.Errorf("%s: %w", confirmationsEnv, perr))
		}
		if n < wallet.DefaultMinConfirmations {
			fmt.Fprintf(os.Stderr, "warning: %s=%d is below the recommended %d; shallow outputs can be undone by a reorg\n", confirmationsEnv, n, wallet.DefaultMinConfirmations)
		}
	}
	return st, func() { st.Close(); w.Close() }
}

// slateArg returns the slate text: a literal argument, or "@file" to read it
// from a file (slates are tens of kilobytes).
func slateArg(a string) string {
	if !strings.HasPrefix(a, "@") {
		return a
	}
	f, err := os.Open(a[1:])
	check(err)
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxSlateFile+1))
	check(err)
	if len(b) > maxSlateFile {
		check(fmt.Errorf("%s is larger than %d bytes; a slate is much smaller", sanitize(a[1:]), maxSlateFile))
	}
	return string(b)
}

// maxSlateFile bounds a slate read from a file.
const maxSlateFile = 1 << 20

// isLoopback reports whether the node address is on this machine.
func isLoopback(addr string) bool {
	h := addr
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexAny(h, "/"); i >= 0 {
		h = h[:i]
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.Trim(h, "[]")
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func newNode(addr string) *wallet.RPCNode {
	n, err := wallet.NewRPCNode(addr, os.Getenv(tokenEnv))
	check(err)
	return n
}

func tipCmd(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: tip <node-rpc>")
		os.Exit(2)
	}
	pretty(callRPC(args[0], "tip", nil))
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
		threads, err := strconv.Atoi(args[2])
		check(err)
		pretty(callRPC(args[1], "startmining", []any{threads, args[3]}))
	case "stop":
		pretty(callRPC(args[1], "stopmining", nil))
	case "stats":
		pretty(callRPC(args[1], "minerstats", nil))
	default:
		usage()
		os.Exit(2)
	}
}

// callRPC performs one call (attaching the bearer token from the environment)
// and returns the decoded response envelope. A JSON-RPC error makes the
// process exit non-zero after printing it.
func callRPC(addr, method string, params []any) any {
	raw, _, err := newNode(addr).CallRaw(method, params)
	check(err)
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		check(fmt.Errorf("node answered with a non-JSON body"))
	}
	if m, ok := out.(map[string]any); ok && m["error"] != nil {
		pretty(out)
		msg := "rpc error"
		if e, ok := m["error"].(map[string]any); ok {
			msg = fmt.Sprint(e["message"])
		}
		fmt.Fprintln(os.Stderr, "error:", sanitize(msg))
		os.Exit(1)
	}
	return out
}

func pretty(v any) {
	body, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(sanitizeMultiline(string(body)))
}

// sanitize makes text from a node (or any error that may embed it) safe to print
// on a terminal: control characters, escape sequences and bidirectional or other
// invisible format characters are replaced, and the length is capped.
func sanitize(s string) string {
	const max = 300
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n >= max {
			b.WriteString("...")
			break
		}
		switch {
		case r == utf8Replacement, unicode.IsControl(r), unicode.Is(unicode.Cf, r), r == '\u2028', r == '\u2029':
			b.WriteRune('?')
		default:
			b.WriteRune(r)
		}
		n++
	}
	return b.String()
}

const utf8Replacement = '\uFFFD'

// sanitizeMultiline is sanitize for pretty-printed JSON: line breaks and
// indentation stay, no length cap.
func sanitizeMultiline(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n' || r == ' ':
			b.WriteRune(r)
		case r == utf8Replacement, unicode.IsControl(r), unicode.Is(unicode.Cf, r), r == '\u2028', r == '\u2029':
			b.WriteRune('?')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// describe prints what is about to be signed or answered: amount, fee, lock
// height and memo (node and memo text are sanitized).
func describe(what string, amount int64, fee, lock uint64, memo, node string) {
	fmt.Fprintf(os.Stderr, "%s\n  amount: %d\n  fee:    %d\n  lock:   %d", what, amount, fee, lock)
	if lock == 0 {
		fmt.Fprint(os.Stderr, " (no lock: it can be mined as soon as it is accepted)")
	} else {
		fmt.Fprint(os.Stderr, " (the transaction cannot be mined before this block height; its outputs are spendable once it is)")
	}
	fmt.Fprintf(os.Stderr, "\n  memo:   %q\n", sanitize(memo))
	if node != "" {
		fmt.Fprintf(os.Stderr, "  node:   %s\n", sanitize(node))
	}
}

// confirm asks on the terminal and exits unless the answer is yes. It does
// nothing with --yes or when stdin is not a terminal (the passphrase is then
// read from stdin and there is nobody to ask).
func confirm(prompt string) {
	if assumeYes || !term.IsTerminal(int(syscall.Stdin)) {
		return
	}
	fmt.Fprint(os.Stderr, prompt)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
		fmt.Fprintln(os.Stderr, "aborted")
		os.Exit(1)
	}
}

// readNewPassphrase asks twice on a terminal; from a pipe it reads one line.
func readNewPassphrase() string {
	fd := int(syscall.Stdin)
	if !term.IsTerminal(fd) {
		return nonEmpty(readPassphraseNonTTY())
	}
	first := readPassphrase(fmt.Sprintf("New passphrase (at least %d characters): ", wallet.MinPassphraseLen))
	if second := readPassphrase("Repeat passphrase: "); second != first {
		check(errors.New("passphrases do not match"))
	}
	return first
}

// readPassphrase prompts on the terminal without echo. When stdin is not a
// terminal (scripts, tests) it reads exactly one line from stdin.
func readPassphrase(prompt string) string {
	fd := int(syscall.Stdin)
	if term.IsTerminal(fd) {
		fmt.Fprint(os.Stderr, prompt)
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		check(err)
		return nonEmpty(string(b))
	}
	return nonEmpty(readPassphraseNonTTY())
}

// readPassphraseNonTTY reads one line from stdin a byte at a time so that no
// input beyond the newline is consumed.
func readPassphraseNonTTY() string {
	var line []byte
	buf := make([]byte, 1)
	for len(line) < 1024 {
		n, err := os.Stdin.Read(buf)
		if n == 1 {
			if buf[0] == '\n' {
				break
			}
			line = append(line, buf[0])
		}
		if err != nil {
			break
		}
	}
	return strings.TrimRight(string(line), "\r")
}

func nonEmpty(s string) string {
	if s == "" {
		check(errors.New("empty passphrase"))
	}
	return s
}

func check(err error) {
	if err != nil {
		// Control characters are stripped everywhere; the length cap applies only to
		// text a node supplied (see callRPC), so instructions in our own errors survive.
		fmt.Fprintln(os.Stderr, "error:", sanitizeMultiline(err.Error()))
		os.Exit(1)
	}
}
