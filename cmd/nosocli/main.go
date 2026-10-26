// nosocli is a command-line wallet/explorer for the archived Noso chain.
//
// It works in two modes:
//
//  1. Offline mode (default): reads NOSODATA directly from disk. All
//     read-only commands (balance, block, supply, halving, address info)
//     are available. Used as a block explorer.
//
//  2. Online mode (when `-node host:port` is set): forwards relevant
//     commands to a running `nosod` instance via the legacy NosoDart
//     TCP protocol. Used for submitting transactions.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pasichDev/noso-go/internal/blockchain"
	"github.com/pasichDev/noso-go/internal/crypto"
	"github.com/pasichDev/noso-go/internal/storage"
)

func main() {
	dataRoot := flag.String("data", "NOSODATA", "path to NOSODATA folder")
	nodeAddr := flag.String("node", "", "address of a running nosod (e.g. 127.0.0.1:8080) for commands that need it")
	flag.Usage = printUsage
	flag.Parse()
	if flag.NArg() < 1 {
		printUsage()
		os.Exit(2)
	}

	cmd := strings.ToLower(flag.Arg(0))
	args := flag.Args()[1:]
	layout := storage.NewLayout(*dataRoot)

	var err error
	switch cmd {
	case "version", "ver":
		fmt.Println("nosocli 0.5.0-go")
	case "supply":
		err = cmdSupply(layout)
	case "halving":
		cmdHalving()
	case "balance":
		err = cmdBalance(layout, *nodeAddr, args)
	case "address":
		err = cmdAddressInfo(layout, args)
	case "block":
		err = cmdBlock(layout, args)
	case "lbinfo":
		err = cmdLastBlock(layout)
	case "summary":
		err = cmdSummary(layout)
	case "newaddress":
		err = cmdNewAddress()
	case "sendto":
		err = cmdSendTo(*nodeAddr, args)
	case "verify-chain":
		err = cmdVerifyChain(layout)
	case "valid":
		err = cmdValidateAddress(args)
	default:
		err = fmt.Errorf("unknown command %q", cmd)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `nosocli — archive explorer / wallet for Noso

Usage:
  nosocli [-data NOSODATA] [-node host:port] <command> [args]

Commands:
  version                       print version
  supply                        expected circulating supply at chain tip
  halving                       print the full reward schedule
  balance <address>             confirmed balance for an address
  address <address>             full account info (balance, alias, lastOp)
  valid <address>               check address checksum
  block <N>                     show block N header and orders
  lbinfo                        last block header
  summary                       sumary.psk statistics
  newaddress                    generate a new key pair + address (prints to stdout)
  sendto <dest> <amount> [memo] submit a TRFR to a running node (needs -node)
  verify-chain                  walk every .blk file and re-validate signatures

Examples:
  nosocli -data /var/noso supply
  nosocli -data /var/noso balance N4PeJyqj8diSXnfhxSQdLpo8ddXTaGd
  nosocli -node 127.0.0.1:8080 sendto Nrecv 100000000 hello
`)
}

func cmdSupply(layout *storage.Layout) error {
	sum, err := storage.NewSummaryStore(layout.Summary)
	if err != nil {
		return err
	}
	total := sum.Total()
	fmt.Printf("accounts:      %d\n", sum.Len())
	fmt.Printf("total balance: %d base units (%s NOSO)\n", total, formatNoso(total))
	hdr, err := storage.NewHeadersStore(layout.Headers)
	if err == nil {
		if tip, ok := hdr.Tip(); ok {
			expected := blockchain.GetSupply(int64(tip.Block))
			fmt.Printf("chain tip:     block %d\n", tip.Block)
			fmt.Printf("expected:      %s NOSO at this height\n", formatNoso(expected))
		}
	}
	return nil
}

func cmdHalving() {
	for era := int64(0); era <= blockchain.HalvingSteps; era++ {
		start := era * blockchain.BlockHalvingInterval
		if era == 0 {
			start = 1 // block 0 is special
		}
		end := (era+1)*blockchain.BlockHalvingInterval - 1
		reward := blockchain.BlockReward(start)
		fmt.Printf("era %2d  blocks %8d..%8d  reward=%s NOSO\n",
			era, start, end, formatNoso(reward))
	}
}

func cmdBalance(layout *storage.Layout, nodeAddr string, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("balance: missing address")
	}
	addr := args[0]
	if !crypto.IsValidAddress(addr) {
		return fmt.Errorf("invalid address %q", addr)
	}
	if nodeAddr != "" {
		return cmdBalanceViaNode(nodeAddr, addr)
	}
	sum, err := storage.NewSummaryStore(layout.Summary)
	if err != nil {
		return err
	}
	rec, ok := sum.Get(addr)
	if !ok {
		fmt.Println("0")
		return nil
	}
	fmt.Printf("%d (%s NOSO)\n", rec.Balance, formatNoso(rec.Balance))
	if rec.Custom != "" {
		fmt.Printf("alias: %s\n", rec.Custom)
	}
	return nil
}

func cmdBalanceViaNode(addr, target string) error {
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintf(c, "NSLBALANCE %s\n", target); err != nil {
		return err
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return err
	}
	fmt.Print(line)
	return nil
}

func cmdAddressInfo(layout *storage.Layout, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("address: missing argument")
	}
	addr := args[0]
	sum, err := storage.NewSummaryStore(layout.Summary)
	if err != nil {
		return err
	}
	rec, ok := sum.Get(addr)
	if !ok {
		fmt.Println("address not in summary")
		return nil
	}
	fmt.Printf("address: %s\n", rec.Hash)
	fmt.Printf("alias:   %s\n", emptyOr(rec.Custom, "(none)"))
	fmt.Printf("balance: %d (%s NOSO)\n", rec.Balance, formatNoso(rec.Balance))
	fmt.Printf("score:   %d\n", rec.Score)
	fmt.Printf("lastOp:  block %d\n", rec.LastOP)
	fmt.Printf("checksum valid: %v\n", crypto.IsValidAddress(addr))
	return nil
}

func cmdBlock(layout *storage.Layout, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("block: missing number")
	}
	n, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		return err
	}
	b, err := layout.ReadBlock(n)
	if err != nil {
		return err
	}
	fmt.Printf("block #%d\n", b.Header.Number)
	fmt.Printf("  timestart: %d\n", b.Header.TimeStart)
	fmt.Printf("  timeend:   %d\n", b.Header.TimeEnd)
	fmt.Printf("  miner:     %s\n", b.Header.AccountMiner)
	fmt.Printf("  reward:    %d (%s NOSO)\n", b.Header.Reward, formatNoso(b.Header.Reward))
	fmt.Printf("  minerFee:  %d\n", b.Header.MinerFee)
	fmt.Printf("  txs:       %d\n", b.Header.TrxTotales)
	fmt.Printf("  target:    %s\n", b.Header.TargetHash)
	fmt.Printf("  prev hash: %s\n", b.Header.LastBlockHash)
	for i, o := range b.Orders {
		fmt.Printf("  [%d] %s  %s -> %s  amount=%d  fee=%d\n",
			i, o.OrderType, o.Address, o.Receiver, o.AmmountTrf, o.AmmountFee)
	}
	return nil
}

func cmdLastBlock(layout *storage.Layout) error {
	hdr, err := storage.NewHeadersStore(layout.Headers)
	if err != nil {
		return err
	}
	tip, ok := hdr.Tip()
	if !ok {
		fmt.Println("no blocks yet")
		return nil
	}
	fmt.Printf("tip block: %d\n", tip.Block)
	fmt.Printf("blockHash: %s\n", tip.BlockHash)
	fmt.Printf("sumHash:   %s\n", tip.SumHash)
	return nil
}

func cmdSummary(layout *storage.Layout) error {
	sum, err := storage.NewSummaryStore(layout.Summary)
	if err != nil {
		return err
	}
	count := sum.Len()
	all := sum.All()
	var valid, withAlias int
	for _, r := range all {
		if crypto.IsValidAddress(r.Hash) {
			valid++
		}
		if r.Custom != "" {
			withAlias++
		}
	}
	fmt.Printf("accounts:        %d\n", count)
	fmt.Printf("valid addresses: %d\n", valid)
	fmt.Printf("with alias:      %d\n", withAlias)
	fmt.Printf("total balance:   %s NOSO\n", formatNoso(sum.Total()))
	return nil
}

func cmdNewAddress() error {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		return err
	}
	addr, err := crypto.AddressFromPublicKey(kp.PublicKey, crypto.AddressTypeRegular)
	if err != nil {
		return err
	}
	fmt.Printf("address:    %s\n", addr)
	fmt.Printf("public key: %s\n", kp.PublicKey)
	fmt.Printf("private:    %s\n", kp.PrivateKey)
	fmt.Println("\n** Save the private key safely. Anyone with it controls the address. **")
	return nil
}

func cmdSendTo(nodeAddr string, args []string) error {
	if nodeAddr == "" {
		return fmt.Errorf("sendto requires -node host:port")
	}
	if len(args) < 2 {
		return fmt.Errorf("sendto: usage: sendto <dest> <amount> [memo]")
	}
	// Wallet integration is not yet wired up; we'd need to load wallet.pkw
	// and pick the default address. For now report the missing piece
	// cleanly so the user knows to use the RPC submitorder once that lands.
	return fmt.Errorf("sendto: wallet selection not implemented yet; use the RPC submitorder method or wire up a default key")
}

func cmdVerifyChain(layout *storage.Layout) error {
	hdr, err := storage.NewHeadersStore(layout.Headers)
	if err != nil {
		return err
	}
	tip, ok := hdr.Tip()
	if !ok {
		fmt.Println("no chain to verify")
		return nil
	}
	var (
		blocksOK, blocksFail int
		ordersOK, ordersBad  int
	)
	for n := int64(0); n <= int64(tip.Block); n++ {
		path := layout.BlockPath(n)
		if _, err := os.Stat(path); err != nil {
			continue // skip missing blocks
		}
		b, err := storage.ReadBlockFile(path)
		if err != nil {
			blocksFail++
			fmt.Fprintf(os.Stderr, "block %d: parse error: %v\n", n, err)
			continue
		}
		blocksOK++
		for i := range b.Orders {
			if blockchain.VerifyOrder(&b.Orders[i]) {
				ordersOK++
			} else {
				ordersBad++
			}
		}
	}
	fmt.Printf("blocks parsed: %d (failed %d)\n", blocksOK, blocksFail)
	fmt.Printf("orders: %d ok, %d bad signatures (or non-TRFR/CUSTOM types)\n", ordersOK, ordersBad)
	return nil
}

func cmdValidateAddress(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("valid: missing address")
	}
	if crypto.IsValidAddress(args[0]) {
		fmt.Println("valid")
		return nil
	}
	fmt.Println("invalid")
	return nil
}

func formatNoso(units int64) string {
	neg := units < 0
	if neg {
		units = -units
	}
	whole := units / 1e8
	frac := units % 1e8
	s := fmt.Sprintf("%d.%08d", whole, frac)
	if neg {
		s = "-" + s
	}
	return s
}

func emptyOr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// hint suppresses unused-import warnings for build environments where the
// flag package may be optimized away by aggressive linters.
var _ = filepath.Join
