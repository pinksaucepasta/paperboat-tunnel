package runtime

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/control"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/tlscert"
)

var (
	ErrCertificateWorkerInvalid = errors.New("invalid certificate distribution worker")
	ErrCertificateWorkerAction  = errors.New("certificate distribution action failed")
)

// CertificateDistributionWorker is the edge-side live distribution loop. It
// mutates the in-memory registry only after the control client has verified
// the server HMAC and the receiver has checked the complete generation
// binding. The worker acknowledges an action only after the local transition
// succeeds, so a lost ACK is safe to replay.
type CertificateDistributionWorker struct {
	client       *control.CertificateDistributionClient
	receiver     *tlscert.DistributionReceiver
	nodeID       string
	processEpoch string
	interval     time.Duration

	mu      sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}
	lastErr error
}

type CertificateDistributionWorkerConfig struct {
	Client       *control.CertificateDistributionClient
	Receiver     *tlscert.DistributionReceiver
	NodeID       string
	ProcessEpoch string
	Interval     time.Duration
}

func NewCertificateDistributionWorker(config CertificateDistributionWorkerConfig) (*CertificateDistributionWorker, error) {
	if config.Client == nil || config.Receiver == nil || config.NodeID == "" || config.ProcessEpoch == "" || config.Interval <= 0 {
		return nil, ErrCertificateWorkerInvalid
	}
	return &CertificateDistributionWorker{client: config.Client, receiver: config.Receiver, nodeID: config.NodeID, processEpoch: config.ProcessEpoch, interval: config.Interval}, nil
}

func (w *CertificateDistributionWorker) Start(ctx context.Context) error {
	if w == nil || w.client == nil || w.receiver == nil || ctx == nil {
		return ErrCertificateWorkerInvalid
	}
	if err := w.reconcile(ctx); err != nil && !errors.Is(err, control.ErrControlUnavailable) {
		return err
	}
	workerCtx, cancel := context.WithCancel(ctx)
	w.mu.Lock()
	if w.cancel != nil || w.done != nil {
		w.mu.Unlock()
		cancel()
		return ErrCertificateWorkerInvalid
	}
	w.cancel, w.done = cancel, make(chan struct{})
	done := w.done
	w.mu.Unlock()
	go func() {
		defer close(done)
		ticker := time.NewTicker(w.interval)
		defer ticker.Stop()
		for {
			select {
			case <-workerCtx.Done():
				return
			case <-ticker.C:
				if err := w.reconcile(workerCtx); err != nil && !errors.Is(err, context.Canceled) {
					w.mu.Lock()
					w.lastErr = err
					w.mu.Unlock()
				}
			}
		}
	}()
	return nil
}

func (w *CertificateDistributionWorker) Shutdown(ctx context.Context) error {
	if w == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	w.mu.Lock()
	cancel, done := w.cancel, w.done
	w.cancel, w.done = nil, nil
	w.mu.Unlock()
	if cancel != nil {
		cancel()
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	// The client owns a verifier copy of the control credential in addition to
	// the receiver's in-memory certificate registry. Wipe both on shutdown,
	// including the no-worker-started path used by partial construction.
	return errors.Join(w.receiver.Close(), w.client.Close())
}

func (w *CertificateDistributionWorker) LastError() error {
	if w == nil {
		return ErrCertificateWorkerInvalid
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.lastErr
}

func (w *CertificateDistributionWorker) reconcile(ctx context.Context) error {
	messages, err := w.client.Pull(ctx, w.nodeID, w.processEpoch)
	if err != nil {
		return err
	}
	for index := range messages {
		if err := w.apply(ctx, messages[index]); err != nil {
			for wipeIndex := range messages {
				tlscert.WipeDistributionEnvelope(&messages[wipeIndex])
			}
			return err
		}
		tlscert.WipeDistributionEnvelope(&messages[index])
	}
	return nil
}

func (w *CertificateDistributionWorker) apply(ctx context.Context, envelope tlscert.DistributionEnvelope) error {
	defer tlscert.WipeDistributionEnvelope(&envelope)
	var status string
	var applyErr error
	switch envelope.Action {
	case "stage":
		applyErr = w.receiver.StageAndReady(ctx, envelope)
		status = "ready"
	case "activate":
		applyErr = w.receiver.Activate(ctx, envelope)
		status = "active"
	case "retire":
		applyErr = w.receiver.Retire(ctx, envelope)
		status = "retired"
	case "revoke":
		applyErr = w.receiver.Revoke(ctx, envelope)
		status = "revoked"
	default:
		applyErr = ErrCertificateWorkerAction
	}
	if applyErr != nil {
		code := boundedCertificateWorkerCode(applyErr)
		if ackErr := w.client.Ack(ctx, envelope, "failed", code); ackErr != nil {
			return errors.Join(fmt.Errorf("%w: %v", ErrCertificateWorkerAction, applyErr), ackErr)
		}
		return fmt.Errorf("%w: %v", ErrCertificateWorkerAction, applyErr)
	}
	if err := w.client.Ack(ctx, envelope, status, ""); err != nil {
		return err
	}
	return nil
}

func boundedCertificateWorkerCode(err error) string {
	if errors.Is(err, tlscert.ErrGenerationConflict) {
		return "generation_conflict"
	}
	if errors.Is(err, tlscert.ErrCertificateExpired) {
		return "certificate_expired"
	}
	if errors.Is(err, tlscert.ErrCertificateRevoked) {
		return "certificate_revoked"
	}
	return "certificate_action_failed"
}

var _ Component = (*CertificateDistributionWorker)(nil)
