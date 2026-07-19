package node

import (
	"context"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/control"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/testedge"
)

func TestRegisterAndHeartbeatReportsDrainObservation(t *testing.T) {
	manager := readyManager(t, 2)
	fake := testedge.New()
	at := time.Unix(100, 0).UTC()
	registration := control.NodeRegistration{NodeID: "edge_test_01", EdgePool: "default", Artifact: "artifact", Protocol: "1.0", ProcessEpoch: "epoch", Capacity: 2}
	if err := manager.RegisterAndHeartbeat(context.Background(), fake, registration, at); err != nil {
		t.Fatal(err)
	}
	observation, ok := fake.Node(registration.NodeID)
	if !ok || !observation.Ready || observation.Draining || !observation.At.Equal(at) {
		t.Fatalf("observation = %+v, %v", observation, ok)
	}
	if !manager.state.BeginDrain(at.Add(time.Minute)) {
		t.Fatal("drain transition failed")
	}
	if err := manager.RegisterAndHeartbeat(context.Background(), fake, registration, at.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	observation, _ = fake.Node(registration.NodeID)
	if observation.Ready || !observation.Draining {
		t.Fatalf("drain observation = %+v", observation)
	}
}
