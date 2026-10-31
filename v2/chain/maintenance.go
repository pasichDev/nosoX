package chain

import "context"

// Reclaim performs at most one backend maintenance attempt. It does not hold
// the chain mutex across disk GC. The backend serializes maintenance with Close
// and protects MVCC readers; a concurrent close may reject the attempt safely.
// Badger cannot interrupt an already-running value-log rewrite. Cancellation
// is checked before and after that bounded synchronous operation.
func (c *Chain) Reclaim(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	store := c.store
	c.mu.Unlock()
	if maintenance, ok := store.(interface{ Reclaim(context.Context) error }); ok {
		return maintenance.Reclaim(ctx)
	}
	return nil
}
