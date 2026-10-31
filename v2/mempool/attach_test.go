package mempool

import (
	"testing"
	"time"

	"github.com/pasichDev/noso-go/v2/chain"
)

func TestAttachLifecycle(t *testing.T) {
	c := chain.NewMemory()
	p := NewValidated(4, okValidator)
	a := Attach(c, p)
	done := make(chan struct{})
	go func() { a.Wait(); a.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Wait/Stop hung")
	}
}
