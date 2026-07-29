package runtime

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestSupervisedProcessRestartsThenRecovers(t *testing.T) {
	marker := t.TempDir() + "/started"
	process, err := NewSupervisedProcess(ProcessSpec{
		Name: "recover", Path: os.Args[0], Args: []string{"-test.run=TestProcessHelper", "--", "recover"},
		Env:            append(os.Environ(), "PAPERBOAT_PROCESS_HELPER=1", "PAPERBOAT_RECOVERY_MARKER="+marker),
		MaxOutputBytes: 1024, RestartLimit: 2, RestartBackoff: 10 * time.Millisecond, RestartMaxWait: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for !process.Running() || func() bool { _, err := os.Stat(marker); return err != nil }() {
		if time.Now().After(deadline) {
			t.Fatal("replacement child did not become healthy")
		}
		time.Sleep(10 * time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := process.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestSupervisedProcessExhaustsBoundedRestarts(t *testing.T) {
	process, err := NewSupervisedProcess(ProcessSpec{
		Name: "exit", Path: os.Args[0], Args: []string{"-test.run=TestProcessHelper", "--", "exit"},
		Env: append(os.Environ(), "PAPERBOAT_PROCESS_HELPER=1"), MaxOutputBytes: 1024,
		RestartLimit: 2, RestartBackoff: time.Millisecond, RestartMaxWait: 2 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-process.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("restart budget did not terminate")
	}
	if process.Err() == nil {
		t.Fatal("restart exhaustion did not surface an error")
	}
}

func TestSupervisedProcessShutdownDuringRestartBackoff(t *testing.T) {
	process, err := NewSupervisedProcess(ProcessSpec{
		Name: "exit", Path: os.Args[0], Args: []string{"-test.run=TestProcessHelper", "--", "exit"},
		Env: append(os.Environ(), "PAPERBOAT_PROCESS_HELPER=1"), MaxOutputBytes: 1024,
		RestartLimit: 3, RestartBackoff: time.Hour, RestartMaxWait: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for process.Running() {
		if time.Now().After(deadline) {
			t.Fatal("child did not exit")
		}
		time.Sleep(time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := process.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-process.Done():
	default:
		t.Fatal("shutdown returned before supervisor stopped")
	}
}
