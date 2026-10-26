package main

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type blockingMaintenance struct {
	started    chan struct{}
	release    chan struct{}
	once       sync.Once
	active     atomic.Int32
	overlapped atomic.Bool
}

func (s *blockingMaintenance) Reclaim(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.active.Add(1) != 1 {
		s.overlapped.Store(true)
	}
	defer s.active.Add(-1)
	s.once.Do(func() { close(s.started) })
	<-s.release
	return errors.New("injected maintenance result")
}
func TestMaintenanceWorkerSerializesAndStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := &blockingMaintenance{started: make(chan struct{}), release: make(chan struct{})}
	var reported atomic.Int32
	done := runStorageMaintenance(ctx, time.Millisecond, store, func(error) { reported.Add(1) })
	select {
	case <-store.started:
	case <-time.After(3 * time.Second):
		t.Fatal("maintenance did not start")
	}
	cancel()
	close(store.release)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("maintenance failed to stop")
	}
	if store.overlapped.Load() || store.active.Load() != 0 {
		t.Fatal("overlapping or leaked maintenance")
	}
	if reported.Load() != 0 {
		t.Fatal("reported canceled maintenance")
	}
}
func TestMaintenanceDisabled(t *testing.T) {
	done := runStorageMaintenance(context.Background(), 0, nil, func(error) { t.Error("disabled worker ran") })
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("disabled worker did not stop")
	}
}
