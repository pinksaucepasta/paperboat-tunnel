package runtime

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// SupervisedProcess owns one child generation at a time and performs a
// bounded number of restarts before surfacing a terminal failure.
type SupervisedProcess struct {
	spec ProcessSpec

	mu       sync.Mutex
	current  *Process
	done     chan struct{}
	wake     chan struct{}
	wakeOnce sync.Once
	err      error
	started  bool
	stopping bool
}

func NewSupervisedProcess(spec ProcessSpec) (*SupervisedProcess, error) {
	if _, err := NewProcess(spec); err != nil {
		return nil, err
	}
	if spec.RestartLimit > 0 && (spec.RestartBackoff <= 0 || spec.RestartMaxWait < spec.RestartBackoff) {
		return nil, ErrProcessInvalid
	}
	return &SupervisedProcess{spec: spec, done: make(chan struct{}), wake: make(chan struct{})}, nil
}

func (p *SupervisedProcess) Start(ctx context.Context) error {
	p.mu.Lock()
	if p.started || p.stopping {
		p.mu.Unlock()
		return ErrProcessInvalid
	}
	child, err := NewProcess(p.spec)
	if err != nil {
		p.mu.Unlock()
		return err
	}
	p.started = true
	p.current = child
	p.mu.Unlock()
	if err := child.Start(ctx); err != nil {
		p.mu.Lock()
		p.err = err
		p.stopping = true
		p.mu.Unlock()
		close(p.done)
		return err
	}
	go p.supervise(ctx)
	return nil
}

func (p *SupervisedProcess) supervise(ctx context.Context) {
	restarts := 0
	var lastErr error
	for {
		p.mu.Lock()
		child := p.current
		stopping := p.stopping
		p.mu.Unlock()
		if stopping {
			close(p.done)
			return
		}
		if child != nil {
			<-child.Done()
			lastErr = child.Err()
			if lastErr == nil {
				lastErr = errors.New("child exited")
			}
		}
		p.mu.Lock()
		if p.stopping {
			p.mu.Unlock()
			close(p.done)
			return
		}
		if restarts >= p.spec.RestartLimit {
			p.err = fmt.Errorf("child restart limit exhausted after %d restarts: %w", restarts, lastErr)
			p.stopping = true
			p.mu.Unlock()
			close(p.done)
			return
		}
		restarts++
		p.mu.Unlock()

		wait := p.spec.RestartBackoff << (restarts - 1)
		if wait > p.spec.RestartMaxWait {
			wait = p.spec.RestartMaxWait
		}
		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
		case <-p.wake:
			if !timer.Stop() {
				<-timer.C
			}
			close(p.done)
			return
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			p.mu.Lock()
			p.stopping = true
			p.mu.Unlock()
			close(p.done)
			return
		}

		next, err := NewProcess(p.spec)
		if err == nil {
			err = next.Start(ctx)
		}
		if err != nil {
			lastErr = err
			p.mu.Lock()
			p.current = nil
			p.mu.Unlock()
			continue
		}
		p.mu.Lock()
		if p.stopping {
			p.mu.Unlock()
			_ = next.Shutdown(context.Background())
			close(p.done)
			return
		}
		p.current = next
		p.mu.Unlock()
	}
}

func (p *SupervisedProcess) Done() <-chan struct{} { return p.done }

func (p *SupervisedProcess) Err() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

func (p *SupervisedProcess) Running() bool {
	p.mu.Lock()
	child, stopping := p.current, p.stopping
	p.mu.Unlock()
	return !stopping && child != nil && child.Running()
}

func (p *SupervisedProcess) Shutdown(ctx context.Context) error {
	p.mu.Lock()
	if !p.started || p.stopping {
		done := p.done
		p.mu.Unlock()
		select {
		case <-done:
			return nil
		default:
			return nil
		}
	}
	p.stopping = true
	child := p.current
	p.mu.Unlock()
	p.wakeOnce.Do(func() { close(p.wake) })
	var err error
	if child != nil {
		err = child.Shutdown(ctx)
	}
	select {
	case <-p.done:
		return err
	case <-ctx.Done():
		return errors.Join(err, ctx.Err())
	}
}

var _ Component = (*SupervisedProcess)(nil)
