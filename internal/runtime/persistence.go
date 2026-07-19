package runtime

import (
	"context"
	"errors"
	"os"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/store"
)

type Persistence struct {
	Path     string
	Restore  func(store.State) error
	Snapshot func() store.State
}

func (p Persistence) Start(context.Context) error {
	if p.Path == "" || p.Restore == nil || p.Snapshot == nil {
		return errors.New("invalid persistence component")
	}
	state, err := store.Load(p.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return p.Restore(state)
}

func (p Persistence) Shutdown(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return store.Save(p.Path, p.Snapshot())
}
