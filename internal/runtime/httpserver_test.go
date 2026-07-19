package runtime

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestPrivateHTTPServerLifecycle(t *testing.T) {
	server, err := NewHTTPServer(HTTPServerSpec{Address: "127.0.0.1:19000", Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), ReadHeaderTimeout: time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	listener := newBlockingListener()
	server.listen = func(string, string) (net.Listener, error) { return listener, nil }
	if err := server.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := server.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := server.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestPrivateHTTPServerRejectsPublicAndUnboundedConfiguration(t *testing.T) {
	tests := []HTTPServerSpec{{Address: "0.0.0.0:19000", Handler: http.NotFoundHandler(), ReadHeaderTimeout: time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 4096}, {Address: "127.0.0.1:0", Handler: http.NotFoundHandler(), ReadHeaderTimeout: time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 4096}, {Address: "127.0.0.1:19000", Handler: http.NotFoundHandler(), MaxHeaderBytes: 4096}, {Address: "127.0.0.1:19000", Handler: http.NotFoundHandler(), ReadHeaderTimeout: time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 0}}
	for _, spec := range tests {
		if _, err := NewHTTPServer(spec); err == nil {
			t.Fatalf("unsafe server accepted: %+v", spec)
		}
	}
}
