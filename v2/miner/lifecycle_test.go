package miner

import (
	"context"
	"testing"
	"time"

	"github.com/pasichDev/nosoX/v2/chain"
	"github.com/pasichDev/nosoX/v2/types"
)

// The daemon's parent context may expire without a direct Stop call.
// An unavailable chain tip makes candidate construction fail and
// exercises the retry path without starting PoW workers.
func TestParentCancellationRestoresIdleAndAllowsRestart(t *testing.T) {
	m := New(chain.NewMemory(), nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	if err := m.Start(ctx, 1, "test"); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case <-m.done:
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("miner did not stop promptly during candidate retry")
	}
	if state := m.Stats().State; state != StateIdle {
		t.Fatalf("miner remained in state %v after context cancellation", state)
	}

	nextCtx, stop := context.WithCancel(context.Background())
	if err := m.Start(nextCtx, 1, "test"); err != nil {
		stop()
		t.Fatalf("completed miner could not be restarted: %v", err)
	}
	stop()
	m.Stop()
	if state := m.Stats().State; state != StateIdle {
		t.Fatalf("miner state after Stop = %v, want idle", state)
	}
}

func TestBlockListenerCanRegisterAnotherListener(t *testing.T) {
	m := &Miner{}
	done := make(chan struct{})
	m.OnNewBlock(func(*types.Block) {
		m.OnNewBlock(func(*types.Block) {})
		close(done)
	})
	go m.emit(&types.Block{})
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("block listener registration deadlocked on emit")
	}
}
