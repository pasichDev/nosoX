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
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/pasichDev/noso-go/v2/chain"
	"github.com/pasichDev/noso-go/v2/genesis"
	"github.com/pasichDev/noso-go/v2/mempool"
	"github.com/pasichDev/noso-go/v2/miner"
	"github.com/pasichDev/noso-go/v2/p2p"
	"github.com/pasichDev/noso-go/v2/rpc"
	"github.com/pasichDev/noso-go/v2/types"
	"github.com/pasichDev/noso-go/v2/wallet"
)

func main() {
	var (
		dataDir        = flag.String("data", "./nosox-data", "data directory")
		rpcAddr        = flag.String("rpc", "127.0.0.1:7780", "JSON-RPC listen address")
		p2pAddr        = flag.String("p2p", "127.0.0.1:7781", "P2P listen address")
		seedAddr       = flag.String("seed", "", "comma-separated libp2p multi-addrs of seed peers")
		relayAddr      = flag.String("relay", "", "comma-separated libp2p multi-addrs of relay nodes (for NAT)")
		httpSeeds      = flag.Bool("http-seeds", false, "fetch the published seed list over HTTPS at startup (see v2/p2p/httpseeds.go)")
		genesisSummary = flag.String("genesis-summary", "", "path to v1 sumary.psk to airdrop into genesis (only used on first start)")
		genesisGVTs    = flag.String("genesis-gvts", "", "path to v1 gvts.psk to carry forward 100 GVT tokens (only used on first start)")
		networkName    = flag.String("network", "testnet", "mainnet | testnet")
		doMine         = flag.Bool("mine", false, "start mining immediately")
		mineThreads    = flag.Int("threads", 1, "mining threads")
		mineReward     = flag.String("reward", "nosox-default", "reward identifier for coinbase output")
		rpcToken       = flag.String("rpc-token", "", "Bearer token for mutating RPC methods; empty = no auth (only safe on 127.0.0.1)")
		rpcTLSCert     = flag.String("rpc-tls-cert", "", "TLS cert file: serve RPC over HTTPS directly from the node (so HTTPS browser apps can connect, no reverse proxy)")
		rpcTLSKey      = flag.String("rpc-tls-key", "", "TLS key file (required with -rpc-tls-cert)")
	)
	flag.Parse()

	logger := log.New(os.Stderr, "nosoxd ", log.LstdFlags|log.Lshortfile)
	if err := validateRPCBind(*rpcAddr, *rpcToken); err != nil {
		logger.Fatal(err)
	}
	if (*rpcTLSCert == "") != (*rpcTLSKey == "") {
		logger.Fatal("both RPC TLS certificate and key are required")
	}
	if *networkName == "mainnet" {
		logger.Fatal("mainnet disabled: unverified genesis and unresolved security release gates; use isolated testnet")
	}
	if *networkName != "mainnet" && *networkName != "testnet" {
		logger.Fatal("unknown network")
	}
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

	mp := mempool.NewValidated(2048, c.ValidateTransaction)
	cbStore, err := wallet.OpenCoinbaseStore(filepath.Join(*dataDir, "coinbases.json"))
	if err != nil {
		logger.Fatalf("open coinbase store: %v", err)
	}
	mn := miner.New(c, mp, cbStore)
	// Network broadcast wiring: every mined block fans out via libp2p.
	// We register the listener after the p2p node is created (below).

	// Listen on TCP and QUIC-v1 (UDP) on the same port. QUIC keeps the node
	// reachable on lossy/mobile networks where TCP connections stall.
	listenAddrs, err := p2pListenAddrs(*p2pAddr)
	if err != nil {
		logger.Fatal(err)
	}
	node, err := p2p.NewLibp2p(listenAddrs, magic, c, mp)
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
	// Pull the live seed list published over HTTPS (e.g. pasichdev.xyz) so
	// new nodes find peers without a binary upgrade. Best-effort: failures
	// are silent and the node falls back to -seed / DNS / DHT. Disable with
	// -http-seeds=false (e.g. for air-gapped or private networks).
	if *httpSeeds {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		boot.Seeds = append(boot.Seeds, p2p.ResolveHTTPSeedStrings(ctx, *networkName)...)
		cancel()
	}
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
	httpSrv := &http.Server{Addr: *rpcAddr, Handler: rpcSvc.HTTPHandler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	rpcTLS := *rpcTLSCert != "" && *rpcTLSKey != ""
	go func() {
		var err error
		if rpcTLS {
			// In-node HTTPS: lets browser apps served over HTTPS (e.g. the
			// GitHub-Pages explorer) talk to the node directly without hitting
			// the mixed-content block — no separate reverse proxy needed.
			err = httpSrv.ListenAndServeTLS(*rpcTLSCert, *rpcTLSKey)
		} else {
			err = httpSrv.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			logger.Printf("rpc: %v", err)
		}
	}()
	scheme := "http"
	if rpcTLS {
		scheme = "https"
	}
	logger.Printf("JSON-RPC on %s://%s", scheme, *rpcAddr)

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

// Preserve the operator's requested host instead of silently exposing all
// interfaces when a numeric loopback bind was requested.
func p2pListenAddrs(addr string) ([]string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid P2P bind: %w", err)
	}
	if _, err = strconv.ParseUint(port, 10, 16); err != nil {
		return nil, fmt.Errorf("invalid P2P port: %w", err)
	}
	if host == "" {
		host = "0.0.0.0"
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("P2P bind requires a numeric IP")
	}
	family := "ip6"
	if ip.To4() != nil {
		family = "ip4"
	}
	prefix := "/" + family + "/" + ip.String()
	return []string{prefix + "/tcp/" + port, prefix + "/udp/" + port + "/quic-v1"}, nil
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

// Unauthenticated administration is restricted to an explicit numeric loopback.
func validateRPCBind(addr, token string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid RPC bind: %w", err)
	}
	ip := net.ParseIP(host)
	if token == "" && (ip == nil || !ip.IsLoopback()) {
		return fmt.Errorf("non-loopback RPC requires -rpc-token")
	}
	return nil
}
