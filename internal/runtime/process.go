package runtime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

var ErrProcessInvalid = errors.New("invalid child process specification")

type ProcessSpec struct {
	Name           string
	Path           string
	Args           []string
	Env            []string
	MaxOutputBytes int64
	StartupGrace   time.Duration
}

type Process struct {
	spec    ProcessSpec
	mu      sync.Mutex
	errMu   sync.Mutex
	cmd     *exec.Cmd
	done    chan struct{}
	waitErr error
	started bool
	closed  bool
}

func NewProcess(spec ProcessSpec) (*Process, error) {
	if strings.TrimSpace(spec.Name) == "" || spec.Path == "" || spec.MaxOutputBytes < 0 {
		return nil, ErrProcessInvalid
	}
	return &Process{spec: spec}, nil
}

func (p *Process) Start(context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.started || p.closed {
		return ErrProcessInvalid
	}
	command := exec.Command(p.spec.Path, p.spec.Args...)
	command.Env = append([]string(nil), p.spec.Env...)
	if len(command.Env) == 0 {
		command.Env = os.Environ()
	}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Stdout = &boundedWriter{destination: os.Stderr, limit: p.spec.MaxOutputBytes}
	command.Stderr = &boundedWriter{destination: os.Stderr, limit: p.spec.MaxOutputBytes}
	if err := command.Start(); err != nil {
		return err
	}
	p.cmd, p.done, p.started = command, make(chan struct{}), true
	go func() {
		err := command.Wait()
		p.errMu.Lock()
		p.waitErr = err
		p.errMu.Unlock()
		close(p.done)
	}()
	if p.spec.StartupGrace > 0 {
		timer := time.NewTimer(p.spec.StartupGrace)
		defer timer.Stop()
		select {
		case <-p.done:
			p.closed = true
			return fmt.Errorf("child exited during startup: %w", p.waitError())
		case <-timer.C:
		}
	}
	return nil
}

func (p *Process) Done() <-chan struct{} {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.done == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return p.done
}

func (p *Process) Err() error { return p.waitError() }

func (p *Process) waitError() error {
	p.errMu.Lock()
	defer p.errMu.Unlock()
	return p.waitErr
}

func (p *Process) Running() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.started || p.done == nil || p.closed {
		return false
	}
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}

func (p *Process) Shutdown(ctx context.Context) error {
	p.mu.Lock()
	if !p.started || p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	command, done := p.cmd, p.done
	p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		if command.Process != nil {
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			_ = command.Process.Kill()
		}
		return err
	}
	if command.Process != nil {
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
	}
	select {
	case <-done:
		return normalizeWaitError(p.waitError())
	case <-ctx.Done():
		if command.Process != nil {
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			_ = command.Process.Kill()
		}
		return ctx.Err()
	}
}

func normalizeWaitError(err error) error {
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return nil
	}
	return err
}

type boundedWriter struct {
	mu             sync.Mutex
	destination    io.Writer
	limit, written int64
}

func (w *boundedWriter) Write(data []byte) (int, error) {
	length := len(data)
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.limit == 0 {
		return len(data), nil
	}
	remaining := w.limit - w.written
	if remaining <= 0 {
		return len(data), nil
	}
	if int64(len(data)) > remaining {
		data = data[:remaining]
	}
	w.written += int64(len(data))
	if w.destination != nil {
		_, _ = w.destination.Write(data)
	}
	return length, nil
}

func closedErrorChannel(err error) <-chan error {
	channel := make(chan error, 1)
	channel <- err
	close(channel)
	return channel
}

var _ io.Writer = (*boundedWriter)(nil)
