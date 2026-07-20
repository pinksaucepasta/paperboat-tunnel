package runtime

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/control"
)

type ControlDependency struct {
	Source      control.RouteSource
	TrustSource control.RevocationSource
	ApplyTrust  func([]byte) error
	NodeID      string
	Interval    time.Duration

	mu      sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}
	lastErr error
}

func (c *ControlDependency) Start(ctx context.Context) error {
	if c.Source == nil || c.TrustSource == nil || c.ApplyTrust == nil || c.NodeID == "" || c.Interval <= 0 {
		return ErrWorkerInvalid
	}
	if _, err := c.Source.DesiredRoutes(ctx, c.NodeID); err != nil {
		return err
	}
	if err := c.refresh(ctx); err != nil {
		return err
	}
	c.mu.Lock()
	workerCtx, cancel := context.WithCancel(ctx)
	c.cancel, c.done = cancel, make(chan struct{})
	done := c.done
	c.mu.Unlock()
	go func() {
		defer close(done)
		ticker := time.NewTicker(c.Interval)
		defer ticker.Stop()
		for {
			select {
			case <-workerCtx.Done():
				return
			case <-ticker.C:
				c.recordError(c.refresh(workerCtx))
			}
		}
	}()
	return nil
}

func (c *ControlDependency) refresh(ctx context.Context) error {
	document, err := c.TrustSource.Revocations(ctx)
	if err != nil {
		return err
	}
	return c.ApplyTrust(document)
}

func (c *ControlDependency) recordError(err error) { c.mu.Lock(); c.lastErr = err; c.mu.Unlock() }
func (c *ControlDependency) LastError() error      { c.mu.Lock(); defer c.mu.Unlock(); return c.lastErr }

func (c *ControlDependency) Shutdown(ctx context.Context) error {
	c.mu.Lock()
	cancel, done := c.cancel, c.done
	c.cancel, c.done = nil, nil
	c.mu.Unlock()
	if cancel == nil {
		return nil
	}
	cancel()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return errors.Join(ErrWorkerInvalid, ctx.Err())
	}
}

var _ Component = (*ControlDependency)(nil)
