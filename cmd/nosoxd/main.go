// nosoxd is the NosoX archive + mining daemon.
//
//   - Loads (or initializes from the empty genesis) chain state.
//   - Serves the JSON-RPC API used by the explorer and CLI wallet.
//   - Listens for P2P gossip on a separate port.
//   - Optionally drives a mining loop; rewards go to fresh keys in coinbases.json.
//
// Usage:
//
//	nosoxd -data /var/nosox -rpc :7780 -p2p :7781
//	nosoxd -data /var/nosox -mine -threads 2 -reward my-label
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/pasichDev/nosoX/v2/chain"
	"github.com/pasichDev/nosoX/v2/genesis"
	"github.com/pasichDev/nosoX/v2/mempool"
	"github.com/pasichDev/nosoX/v2/miner"
	"github.com/pasichDev/nosoX/v2/p2p"
	"github.com/pasichDev/nosoX/v2/rpc"
	"github.com/pasichDev/nosoX/v2/types"
	"github.com/pasichDev/nosoX/v2/wallet"
)

func main() {
	var (
		dataDir     = flag.String("data", "./nosox-data", "data directory")
		rpcAddr     = flag.String("rpc", "127.0.0.1:7780", "JSON-RPC listen address")
		p2pAddr     = flag.String("p2p", "127.0.0.1:7781", "P2P listen address")
		seedAddr    = flag.String("seed", "", "comma-separated libp2p multi-addrs of seed peers")
		relayAddr   = flag.String("relay", "", "comma-separated libp2p multi-addrs of relay nodes, dialed once at startup (no AutoRelay reservation)")
		httpSeeds   = flag.Bool("http-seeds", false, "fetch the published seed list over HTTPS at startup (see v2/p2p/httpseeds.go)")
		networkName = flag.String("network", "testnet", "mainnet | testnet")
		doMine      = flag.Bool("mine", false, "start mining immediately")
		mineThreads = flag.Int("threads", 1, "mining threads")
		mineReward  = flag.String("reward", "nosox-default", "free-form label for this miner, shown in the log only; not part of any block or signature")
		rpcTokenArg = flag.String("rpc-token", "", "removed: set the "+rpcTokenEnv+" environment variable instead (the command line is visible to other users)")
		rpcTLSCert  = flag.String("rpc-tls-cert", "", "TLS cert file: serve RPC over HTTPS directly from the node (so HTTPS browser apps can connect, no reverse proxy)")
		rpcTLSKey   = flag.String("rpc-tls-key", "", "TLS key file (required with -rpc-tls-cert)")
		natPortMap  = flag.Bool("nat-portmap", false, "ask the router for a port mapping via UPnP/NAT-PMP (off by default)")
		allowPriv   = flag.Bool("allow-private-seeds", false, "keep loopback/private/link-local addresses from DNS and HTTPS seed lists (private test networks); explicit -seed addresses are never filtered")
		soloMine    = flag.Bool("solo-mine", false, "mine without waiting for a synced peer, however mining is started (-mine or the startmining RPC): for a fresh single-node network; otherwise the miner idles until at least one peer is connected and none has more work")
		allowedHost = flag.String("rpc-allowed-hosts", "", "comma-separated extra Host header names (no port) the RPC accepts besides localhost and IP literals, e.g. the name a loopback reverse proxy forwards; empty = none")
		corsOrigin  = flag.String("rpc-cors-origin", "", "browser origin allowed to call the RPC (exact origin, or * for any); empty = no CORS headers")
		verifyFull  = flag.Bool("verify-full", false, "replay and verify the whole chain at start even when a verified-history marker exists (use after restoring a data directory from an untrusted source)")
		testDiff    = flag.Uint64("testnet-difficulty", 0, "testnet only: initial difficulty of the testnet genesis (default: the built-in genesis difficulty); changes the genesis hash, so every node of that testnet must use the same value")
	)
	maintenanceInterval := flag.Duration("storage-maintenance", 10*time.Minute, "interval for one bounded storage GC attempt; 0 disables")
	flag.Parse()
	if *maintenanceInterval < 0 {
		log.Fatal("storage-maintenance cannot be negative")
	}

	logger := log.New(os.Stderr, "nosoxd ", log.LstdFlags|log.Lshortfile)
	// Registered first, so it runs after every other deferred cleanup (chain
	// close, pool link): an RPC failure still shuts down cleanly but exits
	// non-zero, which is what makes a supervisor restart the node.
	exitCode := 0
	defer func() {
		if exitCode != 0 {
			os.Exit(exitCode)
		}
	}()
	if *rpcTokenArg != "" {
		logger.Fatalf("-rpc-token was removed: export %s instead (a token on the command line is readable by every local user)", rpcTokenEnv)
	}
	rpcToken, err := rpcTokenFromEnv(os.Getenv)
	if err != nil {
		logger.Fatal(err)
	}
	if (*rpcTLSCert == "") != (*rpcTLSKey == "") {
		logger.Fatal("both RPC TLS certificate and key are required")
	}
	if err := validateRPCConfig(*rpcAddr, rpcToken, *rpcTLSCert != ""); err != nil {
		logger.Fatal(err)
	}
	if *networkName == "mainnet" {
		logger.Fatal("mainnet disabled: unverified genesis and unresolved security release gates; use isolated testnet")
	}
	if *networkName != "mainnet" && *networkName != "testnet" {
		logger.Fatal("unknown network")
	}

	if *testDiff != 0 && *networkName != "testnet" {
		logger.Fatal("-testnet-difficulty is only valid with -network testnet")
	}
	magic := types.NetworkMagicMainnet
	if *networkName == "testnet" {
		magic = types.NetworkMagicTestnet
	}
	// Refuse to start on a tampered or unsigned baked checkpoint set before
	// touching any state on disk.
	checkpoints, err := trustedCheckpoints(magic, types.LauncherPubkey, types.MainnetCheckpointsSig, types.MainnetCheckpoints, types.TestnetCheckpoints)
	if err != nil {
		logger.Fatalf("refusing to start: %v", err)
	}
	if err := prepareDataDir(*dataDir); err != nil {
		logger.Fatalf("data dir: %v", err)
	}

	chainDir := filepath.Join(*dataDir, "chain")
	c, err := chain.NewBadger(chainDir)
	if err != nil {
		logger.Fatalf("open chain badger: %v", err)
	}
	defer func() {
		if err := c.Close(); err != nil {
			logger.Printf("chain close: %v", err)
		}
	}()
	c.SetCheckpoints(checkpoints) // before LoadOrInit so replay is pinned too
	c.SetFullVerify(*verifyFull)
	gCfg := genesis.Default()
	gCfg.NetworkMagic = magic
	if *testDiff != 0 {
		gCfg.InitialDifficulty = *testDiff
		logger.Printf("testnet genesis difficulty overridden to %d", *testDiff)
	}
	gBlock, err := genesis.Build(gCfg)
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
	mp.SetPolicy(mempool.DefaultPolicy)
	poolLink := mempool.Attach(c, mp) // blocks and reorgs keep the pool consistent
	defer poolLink.Stop()
	cbStore, err := wallet.OpenCoinbaseStore(filepath.Join(*dataDir, "coinbases.json"))
	if err != nil {
		logger.Fatalf("open coinbase store: %v", err)
	}
	mn := miner.New(c, mp, cbStore)
	mn.SetLogger(logger.Printf)
	// Network broadcast wiring: every mined block fans out via libp2p.
	// We register the listener after the p2p node is created (below).

	// Listen on TCP and QUIC-v1 (UDP) on the same port. QUIC keeps the node
	// reachable on lossy/mobile networks where TCP connections stall.
	listenAddrs, err := p2pListenAddrs(*p2pAddr)
	if err != nil {
		logger.Fatal(err)
	}
	node, err := p2p.NewLibp2pWithOptions(p2p.Options{ListenAddrs: listenAddrs, Magic: magic, DataDir: *dataDir, NATPortMap: *natPortMap}, c, mp)
	if err != nil {
		logger.Fatalf("p2p: %v", err)
	}
	node.SetLogger(func(format string, args ...any) { logger.Printf("p2p: "+format, args...) })
	if !*soloMine {
		mn.SetSyncGate(minerGate(node))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	maintenanceDone := runStorageMaintenance(ctx, *maintenanceInterval, c, func(err error) { logger.Printf("storage maintenance: %v", err) })
	defer func() { cancel(); <-maintenanceDone }()

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
	// are silent and the node falls back to -seed / DNS. Off unless
	// -http-seeds is given.
	if *httpSeeds {
		seedCtx, seedCancel := context.WithTimeout(context.Background(), 10*time.Second)
		boot.Seeds = append(boot.Seeds, p2p.ResolveHTTPSeedStringsOpts(seedCtx, *networkName, p2p.SeedOptions{AllowPrivate: *allowPriv})...)
		seedCancel()
	}
	boot.AllowPrivateSeeds = *allowPriv
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
		Token:         rpcToken,
		CORSOrigin:    *corsOrigin,
		AllowedHosts:  splitCSV(*allowedHost),
		GenesisConfig: &gCfg,
		BroadcastTx:   node.BroadcastTx, // gossip transactions accepted via submittransaction
	}
	httpSrv := rpcSvc.NewServer(*rpcAddr) // carries the timeouts and the HTTP/2 stream cap
	// Bind before announcing anything: a port already taken, or an unusable
	// certificate, must stop the node, not leave it running without RPC while
	// another local process answers on the port.
	rpcLn, rpcTLSConfig, err := rpcListener(*rpcAddr, *rpcTLSCert, *rpcTLSKey)
	if err != nil {
		logger.Fatal(err)
	}
	rpcErr := serveRPC(httpSrv, rpcLn, rpcTLSConfig)
	scheme := "http"
	if rpcTLSConfig != nil {
		scheme = "https"
	}
	logger.Printf("JSON-RPC on %s://%s", scheme, rpcLn.Addr())

	if *doMine {
		if *mineThreads < 1 || *mineThreads > miner.MaxThreads {
			logger.Fatalf("-threads must be between 1 and %d", miner.MaxThreads)
		}
		if *soloMine {
			if err := mn.Start(ctx, *mineThreads, *mineReward); err != nil {
				logger.Fatalf("miner start: %v", err)
			}
			logger.Printf("miner started (solo) with %d threads, reward=%s", *mineThreads, *mineReward)
		} else {
			// The gate is the miner's, not a one-time wait: it is re-checked before
			// every block and also covers mining started later over RPC.
			if err := mn.Start(ctx, *mineThreads, *mineReward); err != nil {
				logger.Fatalf("miner start: %v", err)
			}
			logger.Printf("miner started with %d threads, reward=%s (it idles while the node is not synced with a peer; use -solo-mine for a single-node network)", *mineThreads, *mineReward)
		}
	}

	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-sig:
	case err := <-rpcErr:
		// The node cannot do its job without RPC: shut down cleanly, but exit
		// non-zero so a supervisor (systemd Restart=on-failure) restarts it.
		logger.Printf("rpc server stopped: %v", err)
		exitCode = 1
	}
	logger.Printf("shutting down")
	go func() { // a second signal aborts a shutdown that hangs
		<-sig
		logger.Printf("second signal: exiting immediately")
		os.Exit(1)
	}()
	cancel()
	<-maintenanceDone

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

// syncGate is what mining depends on: at least one connected peer, and a node
// that considers itself synced with them.
type syncGate interface {
	PeerCount() int
	Synced() bool
}

// minerGate turns a node into the miner's gate. The miner calls it before every
// block, so a node that falls behind (or loses its peers) stops mining, and a
// miner started later over RPC is held to the same rule.
func minerGate(g syncGate) func() bool {
	return func() bool { return g.PeerCount() > 0 && g.Synced() }
}
