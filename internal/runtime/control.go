package runtime

import (
	"context"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/control"
)

type ControlDependency struct {
	Source control.RouteSource
	NodeID string
}

func (c ControlDependency) Start(ctx context.Context) error {
	if c.Source == nil || c.NodeID == "" {
		return ErrWorkerInvalid
	}
	_, err := c.Source.DesiredRoutes(ctx, c.NodeID)
	return err
}

func (c ControlDependency) Shutdown(context.Context) error { return nil }

var _ Component = ControlDependency{}
