package runtime

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
)

type orderedComponent struct {
	name   string
	events *[]string
	mu     *sync.Mutex
	fail   bool
}

func (c orderedComponent) Start(context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	*c.events = append(*c.events, "start:"+c.name)
	if c.fail {
		return errors.New("failed")
	}
	return nil
}
func (c orderedComponent) Shutdown(context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	*c.events = append(*c.events, "stop:"+c.name)
	return nil
}

func TestDataPlaneOrdersStartupAndAccountingSafeShutdown(t *testing.T) {
	var mu sync.Mutex
	var events []string
	component := func(name string) Component { return orderedComponent{name: name, events: &events, mu: &mu} }
	dataPlane, err := NewDataPlane(DataPlaneSpec{Persistence: component("store"), Control: component("control"), Node: component("node"), Routes: component("routes"), Hook: component("hook"), FRPS: component("frps"), Caddy: component("caddy"), Usage: component("usage")})
	if err != nil {
		t.Fatal(err)
	}
	if err := dataPlane.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := dataPlane.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{"start:store", "start:control", "start:node", "start:routes", "start:usage", "start:hook", "start:frps", "start:caddy", "stop:caddy", "stop:frps", "stop:routes", "stop:usage", "stop:node", "stop:hook", "stop:control", "stop:store"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events = %v", events)
	}
}

func TestDataPlaneCleansPartialStartupInReverse(t *testing.T) {
	var mu sync.Mutex
	var events []string
	component := func(name string, fail bool) Component {
		return orderedComponent{name: name, events: &events, mu: &mu, fail: fail}
	}
	dataPlane, _ := NewDataPlane(DataPlaneSpec{Persistence: component("store", false), Control: component("control", false), Node: component("node", false), Routes: component("routes", false), Hook: component("hook", true), FRPS: component("frps", false), Caddy: component("caddy", false), Usage: component("usage", false)})
	if err := dataPlane.Start(context.Background()); err == nil {
		t.Fatal("partial startup succeeded")
	}
	want := []string{"start:store", "start:control", "start:node", "start:routes", "start:usage", "start:hook", "stop:usage", "stop:routes", "stop:node", "stop:control", "stop:store"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events = %v", events)
	}
}
