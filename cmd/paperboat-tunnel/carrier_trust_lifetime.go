package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"sync"
	"time"
)

var errCarrierTrustRefreshRequired = errors.New("carrier process trust refresh required")

// carrierTrustLifetime turns certificate refresh into a normal supervised
// process replacement. The next process receives a new process epoch, key,
// certificate, registration, and admission fence before accepting carriers.
type carrierTrustLifetime struct {
	refreshAt time.Time
	now       func() time.Time

	mu     sync.Mutex
	cancel context.CancelFunc
	wait   chan struct{}
	done   chan error
}

func newCarrierTrustLifetime(certificate tls.Certificate, now time.Time) (*carrierTrustLifetime, error) {
	if len(certificate.Certificate) == 0 {
		return nil, errors.New("carrier process certificate is missing")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, err
	}
	now = now.UTC()
	validity := leaf.NotAfter.Sub(leaf.NotBefore)
	if validity <= 0 || !leaf.NotAfter.After(now) {
		return nil, errors.New("carrier process certificate is expired")
	}
	lead := time.Hour
	if quarter := validity / 4; quarter < lead {
		lead = quarter
	}
	refreshAt := leaf.NotAfter.Add(-lead)
	if refreshAt.Before(now) {
		refreshAt = now
	}
	return &carrierTrustLifetime{refreshAt: refreshAt, now: time.Now, done: make(chan error, 1)}, nil
}

func (l *carrierTrustLifetime) Start(ctx context.Context) error {
	if l == nil || ctx == nil {
		return errors.New("carrier trust lifetime is invalid")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.cancel != nil {
		return errors.New("carrier trust lifetime already started")
	}
	runCtx, cancel := context.WithCancel(ctx)
	l.cancel = cancel
	l.wait = make(chan struct{})
	delay := l.refreshAt.Sub(l.now().UTC())
	if delay < 0 {
		delay = 0
	}
	go func(wait chan struct{}) {
		defer close(wait)
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-runCtx.Done():
			return
		case <-timer.C:
			select {
			case l.done <- errCarrierTrustRefreshRequired:
			default:
			}
		}
	}(l.wait)
	return nil
}

func (l *carrierTrustLifetime) Done() <-chan error {
	if l == nil || l.done == nil {
		return make(chan error)
	}
	return l.done
}

func (l *carrierTrustLifetime) Shutdown(ctx context.Context) error {
	if l == nil || ctx == nil {
		return nil
	}
	l.mu.Lock()
	cancel, wait := l.cancel, l.wait
	l.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if wait == nil {
		return nil
	}
	select {
	case <-wait:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
