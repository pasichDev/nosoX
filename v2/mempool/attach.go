package mempool

import (
	"sync"

	"github.com/pasichDev/nosoX/v2/chain"
)

// Attachment is the link between a chain and a pool created by Attach.
type Attachment struct {
	mu      sync.Mutex
	cond    *sync.Cond
	queue   []chain.Change
	busy    bool
	stopped bool
	done    chan struct{}
}

// Attach keeps p consistent with c: confirmed and conflicting transactions
// leave the pool on every block, and a reorg re-admits the transactions of
// disconnected blocks that are still valid. Changes are applied in order by one
// goroutine, off the chain's write path, because a reorg can mean hundreds of
// full transaction validations. Call Stop on shutdown.
func Attach(c *chain.Chain, p *Pool) *Attachment {
	a := &Attachment{done: make(chan struct{})}
	a.cond = sync.NewCond(&a.mu)
	c.Subscribe(func(ch chain.Change) {
		a.mu.Lock()
		if !a.stopped {
			a.queue = append(a.queue, ch)
			a.cond.Broadcast()
		}
		a.mu.Unlock()
	})
	go func() {
		defer close(a.done)
		for {
			a.mu.Lock()
			for len(a.queue) == 0 && !a.stopped {
				a.cond.Wait()
			}
			if a.stopped {
				a.mu.Unlock()
				return
			}
			ch := a.queue[0]
			a.queue = a.queue[1:]
			a.busy = true
			a.mu.Unlock()
			p.ApplyChange(ch.Disconnected, ch.Connected)
			a.mu.Lock()
			a.busy = false
			a.cond.Broadcast()
			a.mu.Unlock()
		}
	}()
	return a
}

// Wait blocks until every change queued so far has been applied.
func (a *Attachment) Wait() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for (len(a.queue) > 0 || a.busy) && !a.stopped {
		a.cond.Wait()
	}
}

// Stop ends the applier; queued changes are dropped.
func (a *Attachment) Stop() {
	a.mu.Lock()
	a.stopped = true
	a.cond.Broadcast()
	a.mu.Unlock()
	<-a.done
}
