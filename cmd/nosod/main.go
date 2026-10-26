// nosod is the Noso archive-node daemon. It opens NOSODATA, indexes the
// summary in memory, and serves the legacy NosoDart-compatible TCP API on
// the configured port. RPC and CLI tools talk to it via the local network.
//
// Because the Noso mainnet is dead, the daemon does NOT peer with other
// nodes. It is a single-process archive server.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pasichDev/noso-go/internal/network"
	"github.com/pasichDev/noso-go/internal/storage"
)

func main() {
	dataRoot := flag.String("data", "NOSODATA", "path to NOSODATA folder")
	listen := flag.String("listen", "127.0.0.1:8080", "TCP address for the NosoDart-compatible API")
	version := flag.String("version", "0.5.0-go", "version string reported in NODESTATUS")
	flag.Parse()

	logger := log.New(os.Stderr, "nosod ", log.LstdFlags|log.Lshortfile)

	layout := storage.NewLayout(*dataRoot)
	if err := layout.EnsureDirectories(); err != nil {
		logger.Fatalf("ensure directories: %v", err)
	}

	logger.Printf("opening summary at %s", layout.Summary)
	sumStore, err := storage.NewSummaryStore(layout.Summary)
	if err != nil {
		logger.Fatalf("load summary: %v", err)
	}
	logger.Printf("summary loaded: %d accounts, %d base units total", sumStore.Len(), sumStore.Total())

	hdrStore, err := storage.NewHeadersStore(layout.Headers)
	if err != nil {
		logger.Fatalf("load headers: %v", err)
	}
	tip, hasTip := hdrStore.Tip()
	if hasTip {
		logger.Printf("chain tip at block %d (hash %s)", tip.Block, tip.BlockHash)
	} else {
		logger.Printf("no headers found (empty archive)")
	}

	cfg, err := storage.LoadNosoCFG(layout.NosoCFG)
	if err != nil {
		logger.Printf("nosocfg.psk: %v (continuing with defaults)", err)
		cfg = &storage.NosoCFG{}
	}

	svc := &network.Service{
		Summary:       sumStore,
		Headers:       hdrStore,
		SummaryFile:   layout.Summary,
		GVTsFile:      layout.GVTs,
		CFGRaw:        cfg.Raw,
		Version:       *version,
		ProtoVersion:  "2",
		ListenAddress: *listen,
		StartTime:     time.Now(),
		Pending:       network.NewPendingPool(),
	}

	srv := network.NewServer(*listen, logger)
	svc.Register(srv)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := srv.Start(ctx); err != nil {
		logger.Fatalf("start server: %v", err)
	}
	logger.Printf("listening on %s", srv.Addr())

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	logger.Printf("received signal %s, shutting down", sig)

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Printf("shutdown: %v", err)
	}
	fmt.Fprintln(os.Stderr, "bye.")
}
