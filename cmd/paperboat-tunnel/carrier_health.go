package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync/atomic"

	edgeruntime "github.com/pinksaucepasta/paperboat-tunnel/internal/runtime"
)

// This token authenticates only the retained Caddy private access listener.
func newPrivateAccessToken() (string, error) {
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}

type trackedCarrierComponent struct {
	edgeruntime.Component
	running atomic.Bool
}

func (c *trackedCarrierComponent) Start(ctx context.Context) error {
	if err := c.Component.Start(ctx); err != nil {
		return err
	}
	c.running.Store(true)
	return nil
}
func (c *trackedCarrierComponent) Shutdown(ctx context.Context) error {
	c.running.Store(false)
	return c.Component.Shutdown(ctx)
}
