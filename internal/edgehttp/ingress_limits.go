package edgehttp

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/connectorprotocol"
	"golang.org/x/time/rate"
)

const (
	maximumIngressLimitEntries = 4096
	ingressPacingChunk         = 32 << 10
)

var ErrIngressLimitExceeded = errors.New("ingress limit exceeded")

type IngressUsage interface {
	Record(environment, route string, revision uint64, ingress, egress uint64) error
}

type IngressLimitConfig struct {
	Connections int
	OpenRate    rate.Limit
	OpenBurst   int
	ByteRate    rate.Limit
	ByteBurst   int
}

type IngressLimits struct {
	Publication IngressLimitConfig
	Account     IngressLimitConfig

	mu           sync.Mutex
	publications map[string]*ingressLimitState
	accounts     map[string]*ingressLimitState
}

type ingressLimitState struct {
	active   int
	opens    *rate.Limiter
	bytes    *rate.Limiter
	lastUsed time.Time
}

func DefaultIngressLimits() *IngressLimits {
	return &IngressLimits{Publication: IngressLimitConfig{Connections: 64, OpenRate: 10, OpenBurst: 32, ByteRate: 8 << 20, ByteBurst: 256 << 10}, Account: IngressLimitConfig{Connections: 128, OpenRate: 50, OpenBurst: 128, ByteRate: 32 << 20, ByteBurst: 1 << 20}}
}

func newIngressLimits(config *IngressLimits) (*IngressLimits, error) {
	if config == nil {
		config = DefaultIngressLimits()
	}
	if !validIngressLimit(config.Publication) || !validIngressLimit(config.Account) {
		return nil, ErrIngressLimitExceeded
	}
	return &IngressLimits{Publication: config.Publication, Account: config.Account, publications: make(map[string]*ingressLimitState), accounts: make(map[string]*ingressLimitState)}, nil
}

func validIngressLimit(config IngressLimitConfig) bool {
	return config.Connections > 0 && config.OpenRate > 0 && config.OpenBurst > 0 && config.ByteRate > 0 && config.ByteBurst >= ingressPacingChunk
}

type IngressLease struct {
	limits      *IngressLimits
	publication *ingressLimitState
	account     *ingressLimitState
	decision    connectorprotocol.IngressDecision
	usage       IngressUsage
	once        sync.Once
}

// AcquireIngress is called only after authority validation and before opening
// a carrier stream. The returned lease wraps application bytes after the
// ingress decision preface has been written.
func (r *DataCarrierRouteRegistry) AcquireIngress(ctx context.Context, decision connectorprotocol.IngressDecision) (*IngressLease, error) {
	if r == nil || ctx == nil || decision.Validate(time.Now().UTC()) != nil || r.ingressLimits == nil {
		return nil, ErrIngressLimitExceeded
	}
	return r.ingressLimits.acquire(decision, r.usage)
}

func (l *IngressLimits) acquire(decision connectorprotocol.IngressDecision, usage IngressUsage) (*IngressLease, error) {
	now := time.Now()
	publicationKey := decision.Binding.AccountID + "\x00" + decision.Binding.PublicationID
	accountKey := decision.Binding.AccountID
	l.mu.Lock()
	defer l.mu.Unlock()
	l.expireIdle(now)
	publication := l.publications[publicationKey]
	account := l.accounts[accountKey]
	newEntries := 0
	if publication == nil {
		newEntries++
	}
	if account == nil {
		newEntries++
	}
	if len(l.publications)+len(l.accounts)+newEntries > maximumIngressLimitEntries {
		return nil, ErrIngressLimitExceeded
	}
	if publication == nil {
		publication = newIngressLimitState(l.Publication, now)
	}
	if account == nil {
		account = newIngressLimitState(l.Account, now)
	}
	if publication.active >= l.Publication.Connections || account.active >= l.Account.Connections || publication.opens.TokensAt(now) < 1 || account.opens.TokensAt(now) < 1 {
		return nil, ErrIngressLimitExceeded
	}
	publication.opens.AllowN(now, 1)
	account.opens.AllowN(now, 1)
	publication.active++
	account.active++
	publication.lastUsed, account.lastUsed = now, now
	l.publications[publicationKey], l.accounts[accountKey] = publication, account
	return &IngressLease{limits: l, publication: publication, account: account, decision: decision, usage: usage}, nil
}

func newIngressLimitState(config IngressLimitConfig, now time.Time) *ingressLimitState {
	return &ingressLimitState{opens: rate.NewLimiter(config.OpenRate, config.OpenBurst), bytes: rate.NewLimiter(config.ByteRate, config.ByteBurst), lastUsed: now}
}

func (l *IngressLimits) expireIdle(now time.Time) {
	for key, state := range l.publications {
		if state.active == 0 && now.Sub(state.lastUsed) >= time.Minute && state.opens.TokensAt(now) >= float64(state.opens.Burst()) && state.bytes.TokensAt(now) >= float64(state.bytes.Burst()) {
			delete(l.publications, key)
		}
	}
	for key, state := range l.accounts {
		if state.active == 0 && now.Sub(state.lastUsed) >= time.Minute && state.opens.TokensAt(now) >= float64(state.opens.Burst()) && state.bytes.TokensAt(now) >= float64(state.bytes.Burst()) {
			delete(l.accounts, key)
		}
	}
}

func (l *IngressLease) Wrap(ctx context.Context, stream io.ReadWriteCloser) io.ReadWriteCloser {
	return &meteredIngressStream{ctx: ctx, stream: stream, lease: l}
}

func (l *IngressLease) Release() {
	if l == nil {
		return
	}
	l.once.Do(func() {
		now := time.Now()
		l.limits.mu.Lock()
		l.publication.active--
		l.account.active--
		l.publication.lastUsed, l.account.lastUsed = now, now
		l.limits.mu.Unlock()
	})
}

type meteredIngressStream struct {
	ctx    context.Context
	stream io.ReadWriteCloser
	lease  *IngressLease
	once   sync.Once
}

func (s *meteredIngressStream) Read(payload []byte) (int, error)  { return s.transfer(payload, false) }
func (s *meteredIngressStream) Write(payload []byte) (int, error) { return s.transfer(payload, true) }

func (s *meteredIngressStream) transfer(payload []byte, ingress bool) (int, error) {
	total := 0
	for len(payload) > 0 {
		chunk := len(payload)
		if chunk > ingressPacingChunk {
			chunk = ingressPacingChunk
		}
		if err := s.wait(chunk); err != nil {
			return total, err
		}
		var n int
		var err error
		if ingress {
			n, err = s.stream.Write(payload[:chunk])
		} else {
			n, err = s.stream.Read(payload[:chunk])
		}
		if n > 0 {
			total += n
			if s.lease.usage != nil {
				var usageErr error
				if ingress {
					usageErr = s.lease.usage.Record(s.lease.decision.Binding.EnvironmentID, s.lease.decision.Binding.RouteID, s.lease.decision.Binding.RouteGeneration, uint64(n), 0)
				} else {
					usageErr = s.lease.usage.Record(s.lease.decision.Binding.EnvironmentID, s.lease.decision.Binding.RouteID, s.lease.decision.Binding.RouteGeneration, 0, uint64(n))
				}
				if usageErr != nil {
					return total, usageErr
				}
			}
		}
		payload = payload[n:]
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrNoProgress
		}
		if !ingress {
			return total, nil
		}
	}
	return total, nil
}

func (s *meteredIngressStream) wait(bytes int) error {
	if err := s.lease.publication.bytes.WaitN(s.ctx, bytes); err != nil {
		return err
	}
	return s.lease.account.bytes.WaitN(s.ctx, bytes)
}

func (s *meteredIngressStream) CloseWrite() error {
	if closer, ok := s.stream.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return errors.New("ingress stream does not support TCP half-close")
}

func (s *meteredIngressStream) Close() error {
	var err error
	s.once.Do(func() { err = s.stream.Close(); s.lease.Release() })
	return err
}
