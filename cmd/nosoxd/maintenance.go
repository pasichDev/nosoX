package main

import (
	"context"
	"time"
)

type storageMaintainer interface{ Reclaim(context.Context) error }

// One worker and one attempt per tick: no unbounded GC loop or detached retry.
func runStorageMaintenance(ctx context.Context, interval time.Duration, store storageMaintainer, report func(error)) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		if interval <= 0 {
			return
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := store.Reclaim(ctx); err != nil && ctx.Err() == nil {
					report(err)
				}
			}
		}
	}()
	return done
}
