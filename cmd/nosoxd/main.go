// nosoxd is the Noso v2 archive + mining daemon.
//
//   - Loads (or initializes from genesis) chain state.
//   - Serves the JSON-RPC API used by the explorer and CLI wallet.
//   - Listens for P2P gossip on a separate port.
//   - Optionally drives a mining loop bound to a reward address.
//
// Usage:
//
//	nosoxd -data /var/nosox -rpc :7780 -p2p :7781
//	nosoxd -data /var/nosox -mine -threads 2 -reward NOSOXminerKey
//
// To bootstrap a fresh chain that inherits the v1 chain's balances:
//
//	nosoxd -data /var/nosox -genesis-summary /path/to/sumary.psk
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/noso-project/noso-go/v2/chain"
	"github.com/noso-project/noso-go/v2/genesis"
	"github.com/noso-project/noso-go/v2/mempool"
	"github.com/noso-project/noso-go/v2/miner"
	"github.com/noso-project/noso-go/v2/p2p"
	"github.com/noso-project/noso-go/v2/rpc"
	"github.com/noso-project/noso-go/v2/types"
	"github.com/noso-project/noso-go/v2/wallet"
)

func main() {
	var (
		dataDir         = flag.String("data", "./nosox-data", "data directory")
		rpcAddr         = flag.String("rpc", ":7780", "JSON-RPC listen address")
		p2pAddr         = flag.String("p2p", ":7781", "P2P listen address")
		seedAddr        = flag.String("seed", "", "comma-separated libp2p multi-addrs of seed peers")
		relayAddr       = flag.String("relay", "", "comma-separated libp2p multi-addrs of relay nodes (for NAT)")
		genesisSummary  = flag.String("genesis-summary", "", "path to v1 sumary.psk to airdrop into genesis (only used on first start)")
		genesisGVTs     = flag.String("genesis-gvts", "", "path to v1 gvts.psk to carry forward 100 GVT tokens (only used on first start)")
		networkName     = flag.String("network", "mainnet", "mainnet | testnet")
		doMine          = flag.Bool("mine", false, "start mining immediately")
		mineThreads     = flag.Int("threads", 1, "mining threads")
		mineReward      = flag.String("reward", "nosox-default", "reward identifier for coinbase output")
		rpcToken        = flag.String("rpc-token", "", "Bearer token for mutating RPC methods; empty = no auth (only safe on 127.0.0.1)")
	)
	flag.Parse()

	logger := log.New(os.Stderr, "nosoxd ", log.LstdFlags|log.Lshortfile)
	if err := os.MkdirAll(*dataDir, 0o755); err != nil {
		logger.Fatalf("data dir: %v", err)
	}

	magic := types.NetworkMagicMainnet
	if *networkName == "testnet" {
		magic = types.NetworkMagicTestnet
	}

	chainDir := filepath.Join(*dataDir, "chain")
	c, err := chain.NewBadger(chainDir)
	if err != nil {
		logger.Fatalf("open chain badger: %v", err)
	}
	defer c.Close()
	gCfg := genesis.Default()
	gCfg.SummaryPath = *genesisSummary
	gCfg.GVTsPath = *genesisGVTs
	gCfg.NetworkMagic = magic
	gBlock, _, _, err := genesis.Build(gCfg)
	if err != nil {
		logger.Fatalf("build genesis: %v", err)
	}
	if err := c.LoadOrInit(chainDir, gBlock); err != nil {
		logger.Fatalf("load chain: %v", err)
	}
	tip, _ := c.Tip()
	logger.Printf("chain ready: height=%d hash=%s difficulty=%d",
		tip.Height, types.HeaderID(&tip), tip.Difficulty)

	mp := mempool.New(2048)
	cbStore, err := wallet.OpenCoinbaseStore(filepath.Join(*dataDir, "coinbases.json"))
	if err != nil {
		logger.Fatalf("open coinbase store: %v", err)
	}
	mn := miner.New(c, mp, cbStore)
	// Network broadcast wiring: every mined block fans out via libp2p.
	// We register the listener after the p2p node is created (below).

	node, err := p2p.NewLibp2p([]string{"/ip4/0.0.0.0/tcp" + p2pAddrToPort(*p2pAddr)}, magic, c, mp)
	if err != nil {
		logger.Fatalf("p2p: %v", err)
	}
	node.SetLogger(func(format string, args ...any) { logger.Printf("p2p: "+format, args...) })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := node.Start(); err != nil {
		logger.Fatalf("p2p start: %v", err)
	}
	for _, a := range node.Addrs() {
		logger.Printf("p2p listening on %s", a)
	}

	// Default bootstrap (network seeds + relays) + user-provided overrides.
	boot := p2p.DefaultBootstrap(*networkName)
	boot.Seeds = append(boot.Seeds, splitCSV(*seedAddr)...)
	boot.Relays = append(boot.Relays, splitCSV(*relayAddr)...)
	node.Bootstrap(boot)

	// Mined blocks must gossip. Register a non-blocking publisher.
	mn.OnNewBlock(func(b *types.Block) {
		go func() {
			if err := node.BroadcastBlock(b); err != nil {
				logger.Printf("broadcast block %d: %v", b.Header.Height, err)
			}
		}()
	})

	rpcSvc := &rpc.Service{
		Chain:         c,
		Mempool:       mp,
		Miner:         mn,
		Version:       "0.1.0-nosox",
		DaemonContext: ctx, // long-lived daemon ctx for mining workers
		Token:         *rpcToken,
		GenesisConfig: &gCfg,
	}
	if *rpcToken == "" && !strings.HasPrefix(*rpcAddr, "127.") && !strings.HasPrefix(*rpcAddr, "localhost") {
		logger.Printf("WARNING: RPC bound on %s with no -rpc-token; mutating "+
			"methods are unprotected. Pass -rpc-token or bind 127.0.0.1.", *rpcAddr)
	}
	httpSrv := &http.Server{Addr: *rpcAddr, Handler: rpcSvc.HTTPHandler()}
	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Printf("rpc: %v", err)
		}
	}()
	logger.Printf("JSON-RPC on http://%s", *rpcAddr)

	if *doMine {
		if err := mn.Start(ctx, *mineThreads, *mineReward); err != nil {
			logger.Printf("miner start: %v", err)
		} else {
			logger.Printf("miner started with %d threads, reward=%s", *mineThreads, *mineReward)
		}
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	logger.Printf("shutting down")

	mn.Stop()
	ctxShutdown, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShutdown()
	_ = httpSrv.Shutdown(ctxShutdown)
	_ = node.Shutdown()
	if err := c.Save(); err != nil {
		logger.Printf("chain save: %v", err)
	}
	fmt.Fprintln(os.Stderr, "bye.")
}

// p2pAddrToPort takes a host:port pair (e.g. ":7781" or "0.0.0.0:7781")
// and returns just the "/port" segment expected by libp2p multi-addrs.
func p2pAddrToPort(s string) string {
	if idx := strings.LastIndex(s, ":"); idx >= 0 {
		return "/" + s[idx+1:]
	}
	return "/7781"
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	return out
}
