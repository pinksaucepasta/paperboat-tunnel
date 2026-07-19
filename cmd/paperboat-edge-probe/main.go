package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const websocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

type target struct {
	canceled    atomic.Uint64
	uploadBytes atomic.Uint64
}

func main() {
	mode := flag.String("mode", "", "serve or verify")
	address := flag.String("address", "127.0.0.1:18085", "target listen or edge dial address")
	host := flag.String("host", "phase3.hexwagon.com", "public route host")
	concurrency := flag.Int("concurrency", 32, "load workers")
	duration := flag.Duration("duration", 30*time.Second, "load duration")
	flag.Parse()
	var err error
	switch *mode {
	case "serve":
		err = serve(*address)
	case "verify":
		err = verify(*address, *host)
	case "load":
		err = load(*address, *host, *concurrency, *duration)
	default:
		err = errors.New("mode must be serve, verify, or load")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func serve(address string) error {
	t := &target{}
	mux := http.NewServeMux()
	mux.HandleFunc("/echo", t.echo)
	mux.HandleFunc("/upload", t.upload)
	mux.HandleFunc("/sse", t.sse)
	mux.HandleFunc("/stream", t.stream)
	mux.HandleFunc("/cancel", t.cancel)
	mux.HandleFunc("/stats", t.stats)
	mux.HandleFunc("/upload-bytes", t.uploadStats)
	mux.HandleFunc("/ws", t.websocket)
	server := &http.Server{Addr: address, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	return server.ListenAndServe()
}

func (t *target) echo(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
	if err != nil {
		http.Error(w, "read failed", http.StatusBadRequest)
		return
	}
	response := map[string]any{"method": r.Method, "path": r.URL.RequestURI(), "body": string(body), "forwarded_proto": r.Header.Get("X-Forwarded-Proto"), "forwarded_for": r.Header.Get("X-Forwarded-For"), "spoof": r.Header.Get("X-Paperboat-Environment")}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func (t *target) upload(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	hash := sha1.New()
	size, err := io.Copy(io.MultiWriter(hash, counterWriter{counter: &t.uploadBytes}), r.Body)
	if err != nil {
		http.Error(w, "read failed", http.StatusBadRequest)
		return
	}
	_, _ = fmt.Fprintf(w, "%d:%s", size, hex.EncodeToString(hash.Sum(nil)))
}

func (t *target) sse(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "stream unavailable", http.StatusInternalServerError)
		return
	}
	for i := 1; i <= 3; i++ {
		_, _ = fmt.Fprintf(w, "data: event-%d\n\n", i)
		flusher.Flush()
		time.Sleep(120 * time.Millisecond)
	}
}

func (t *target) stream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "stream unavailable", http.StatusInternalServerError)
		return
	}
	for i := 0; i < 32; i++ {
		select {
		case <-r.Context().Done():
			return
		default:
		}
		_, _ = fmt.Fprintf(w, "%04d:%s\n", i, strings.Repeat("s", 4096))
		flusher.Flush()
		time.Sleep(25 * time.Millisecond)
	}
}

func (t *target) cancel(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	if flusher, ok := w.(http.Flusher); ok {
		_, _ = io.WriteString(w, "started\n")
		flusher.Flush()
	}
	<-r.Context().Done()
	t.canceled.Add(1)
}

func (t *target) stats(w http.ResponseWriter, _ *http.Request) {
	_, _ = fmt.Fprintf(w, "%d", t.canceled.Load())
}

func (t *target) uploadStats(w http.ResponseWriter, _ *http.Request) {
	_, _ = fmt.Fprintf(w, "%d", t.uploadBytes.Load())
}

type counterWriter struct{ counter *atomic.Uint64 }

func (w counterWriter) Write(data []byte) (int, error) {
	w.counter.Add(uint64(len(data)))
	return len(data), nil
}

func (t *target) websocket(w http.ResponseWriter, r *http.Request) {
	if !headerToken(r.Header, "Connection", "upgrade") || !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		http.Error(w, "upgrade required", http.StatusUpgradeRequired)
		return
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		http.Error(w, "key required", http.StatusBadRequest)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "upgrade unavailable", http.StatusInternalServerError)
		return
	}
	connection, rw, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer connection.Close()
	accept := sha1.Sum([]byte(key + websocketGUID))
	_, _ = fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(accept[:]))
	_ = rw.Flush()
	opcode, payload, err := readFrame(rw.Reader)
	if err != nil || opcode != 1 {
		return
	}
	_ = writeFrame(rw.Writer, 1, payload, false)
	_ = rw.Flush()
}

func verify(address, host string) error {
	client := edgeClient(address, host, 64)
	base := "https://" + net.JoinHostPort(host, portOf(address))
	if err := verifyEcho(client, base); err != nil {
		return err
	}
	if err := verifyUpload(client, base); err != nil {
		return err
	}
	if err := verifySSE(client, base); err != nil {
		return err
	}
	if err := verifyStream(client, base); err != nil {
		return err
	}
	if err := verifyCancellation(client, base); err != nil {
		return err
	}
	if err := verifyWebSocket(address, host); err != nil {
		return err
	}
	fmt.Println("echo upload sse stream cancellation websocket: pass")
	return nil
}

func load(address, host string, concurrency int, duration time.Duration) error {
	if concurrency < 1 || concurrency > 512 || duration < time.Second || duration > 10*time.Minute {
		return errors.New("invalid load bounds")
	}
	client := edgeClient(address, host, concurrency*2)
	base := "https://" + net.JoinHostPort(host, portOf(address))
	startedLoad := time.Now()
	deadline := startedLoad.Add(duration)
	var successes, failures atomic.Uint64
	latencies := make(chan time.Duration, 1_000_000)
	done := make(chan struct{}, concurrency)
	payload := strings.Repeat("l", 1024)
	for range concurrency {
		go func() {
			defer func() { done <- struct{}{} }()
			for time.Now().Before(deadline) {
				started := time.Now()
				request, _ := http.NewRequest(http.MethodPost, base+"/echo?load=1", strings.NewReader(payload))
				response, err := client.Do(request)
				if err == nil {
					_, err = io.Copy(io.Discard, response.Body)
					response.Body.Close()
					if response.StatusCode != http.StatusOK {
						err = fmt.Errorf("status %d", response.StatusCode)
					}
				}
				if err != nil {
					failures.Add(1)
					continue
				}
				successes.Add(1)
				select {
				case latencies <- time.Since(started):
				default:
				}
			}
		}()
	}
	for range concurrency {
		<-done
	}
	close(latencies)
	elapsed := time.Since(startedLoad)
	values := make([]time.Duration, 0, len(latencies))
	for value := range latencies {
		values = append(values, value)
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	p95 := time.Duration(0)
	if len(values) != 0 {
		p95 = values[(len(values)-1)*95/100]
	}
	result := map[string]any{"successes": successes.Load(), "failures": failures.Load(), "duration_seconds": elapsed.Seconds(), "requests_per_second": float64(successes.Load()) / elapsed.Seconds(), "p95_milliseconds": float64(p95.Microseconds()) / 1000, "concurrency": concurrency}
	encoded, _ := json.Marshal(result)
	fmt.Println(string(encoded))
	if successes.Load() == 0 || failures.Load() != 0 {
		return errors.New("load failures observed")
	}
	return nil
}

func edgeClient(address, host string, idle int) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, address)
	}, TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: host, MinVersion: tls.VersionTLS12}, ForceAttemptHTTP2: true, MaxIdleConns: idle, MaxIdleConnsPerHost: idle}
	return &http.Client{Transport: transport, Timeout: 10 * time.Second}
}

func verifyEcho(client *http.Client, base string) error {
	request, _ := http.NewRequest(http.MethodPost, base+"/echo?q=one", strings.NewReader("paperboat-echo"))
	request.Header.Set("X-Forwarded-For", "203.0.113.9")
	request.Header.Set("X-Paperboat-Environment", "spoofed")
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("echo: %w", err)
	}
	defer response.Body.Close()
	var got map[string]any
	if err := json.NewDecoder(response.Body).Decode(&got); err != nil {
		return fmt.Errorf("echo decode: %w", err)
	}
	if response.StatusCode != http.StatusOK || got["method"] != "POST" || got["path"] != "/echo?q=one" || got["body"] != "paperboat-echo" || got["forwarded_proto"] != "https" || got["spoof"] != "" || got["forwarded_for"] == "203.0.113.9" {
		return fmt.Errorf("echo mismatch: status=%d response=%v", response.StatusCode, got)
	}
	return nil
}

func verifyUpload(client *http.Client, base string) error {
	payload := bytes.Repeat([]byte("paperboat-upload-"), 128<<10)
	hash := sha1.Sum(payload)
	response, err := client.Post(base+"/upload", "application/octet-stream", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("upload: %w", err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	want := strconv.Itoa(len(payload)) + ":" + hex.EncodeToString(hash[:])
	if response.StatusCode != http.StatusOK || string(body) != want {
		return fmt.Errorf("upload mismatch: status=%d body=%q", response.StatusCode, body)
	}
	return nil
}

func verifySSE(client *http.Client, base string) error {
	started := time.Now()
	response, err := client.Get(base + "/sse")
	if err != nil {
		return fmt.Errorf("sse: %w", err)
	}
	defer response.Body.Close()
	reader := bufio.NewReader(response.Body)
	line, err := reader.ReadString('\n')
	if err != nil || line != "data: event-1\n" || time.Since(started) > 300*time.Millisecond {
		return fmt.Errorf("sse was buffered: line=%q elapsed=%s err=%v", line, time.Since(started), err)
	}
	rest, _ := io.ReadAll(reader)
	if !bytes.Contains(rest, []byte("event-3")) {
		return errors.New("sse final event missing")
	}
	return nil
}

func verifyStream(client *http.Client, base string) error {
	started := time.Now()
	response, err := client.Get(base + "/stream")
	if err != nil {
		return fmt.Errorf("stream: %w", err)
	}
	defer response.Body.Close()
	buffer := make([]byte, 4096)
	if _, err := io.ReadFull(response.Body, buffer); err != nil || time.Since(started) > 300*time.Millisecond {
		return fmt.Errorf("stream was buffered: elapsed=%s err=%v", time.Since(started), err)
	}
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		return fmt.Errorf("stream remainder: %w", err)
	}
	return nil
}

func verifyCancellation(client *http.Client, base string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/cancel", nil)
	response, err := client.Do(request)
	if err == nil {
		_, _ = io.Copy(io.Discard, response.Body)
		response.Body.Close()
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		response, getErr := client.Get(base + "/stats")
		if getErr == nil {
			body, _ := io.ReadAll(response.Body)
			response.Body.Close()
			if strings.TrimSpace(string(body)) != "0" {
				return nil
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errors.New("cancellation did not reach target")
}

func verifyWebSocket(address, host string) error {
	connection, err := tls.Dial("tcp", address, &tls.Config{InsecureSkipVerify: true, ServerName: host, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
	if err != nil {
		return fmt.Errorf("websocket dial: %w", err)
	}
	defer connection.Close()
	var nonce [16]byte
	_, _ = rand.Read(nonce[:])
	key := base64.StdEncoding.EncodeToString(nonce[:])
	_, _ = fmt.Fprintf(connection, "GET /ws HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n", net.JoinHostPort(host, portOf(address)), key)
	reader := bufio.NewReader(connection)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil || response.StatusCode != http.StatusSwitchingProtocols {
		return fmt.Errorf("websocket handshake: status=%v err=%v", statusOf(response), err)
	}
	payload := []byte("paperboat-websocket")
	if err := writeFrame(connection, 1, payload, true); err != nil {
		return fmt.Errorf("websocket write: %w", err)
	}
	opcode, echoed, err := readFrame(reader)
	if err != nil || opcode != 1 || !bytes.Equal(echoed, payload) {
		return fmt.Errorf("websocket echo: opcode=%d payload=%q err=%v", opcode, echoed, err)
	}
	return nil
}

func readFrame(reader io.Reader) (byte, []byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return 0, nil, err
	}
	length := uint64(header[1] & 0x7f)
	if length == 126 {
		var value uint16
		if err := binary.Read(reader, binary.BigEndian, &value); err != nil {
			return 0, nil, err
		}
		length = uint64(value)
	} else if length == 127 {
		if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
			return 0, nil, err
		}
	}
	if length > 1<<20 {
		return 0, nil, errors.New("websocket frame too large")
	}
	var mask [4]byte
	masked := header[1]&0x80 != 0
	if masked {
		if _, err := io.ReadFull(reader, mask[:]); err != nil {
			return 0, nil, err
		}
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return 0, nil, err
	}
	if masked {
		for index := range payload {
			payload[index] ^= mask[index%4]
		}
	}
	return header[0] & 0x0f, payload, nil
}

func writeFrame(writer io.Writer, opcode byte, payload []byte, masked bool) error {
	header := []byte{0x80 | opcode}
	maskBit := byte(0)
	if masked {
		maskBit = 0x80
	}
	switch {
	case len(payload) < 126:
		header = append(header, maskBit|byte(len(payload)))
	case len(payload) <= 65535:
		header = append(header, maskBit|126, byte(len(payload)>>8), byte(len(payload)))
	default:
		header = append(header, maskBit|127, 0, 0, 0, 0, byte(len(payload)>>24), byte(len(payload)>>16), byte(len(payload)>>8), byte(len(payload)))
	}
	data := append([]byte(nil), payload...)
	if masked {
		var mask [4]byte
		if _, err := rand.Read(mask[:]); err != nil {
			return err
		}
		header = append(header, mask[:]...)
		for index := range data {
			data[index] ^= mask[index%4]
		}
	}
	if _, err := writer.Write(header); err != nil {
		return err
	}
	_, err := writer.Write(data)
	return err
}

func headerToken(header http.Header, name, token string) bool {
	for _, part := range strings.Split(header.Get(name), ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}
	return false
}

func portOf(address string) string {
	_, port, err := net.SplitHostPort(address)
	if err == nil {
		return port
	}
	return "18443"
}

func statusOf(response *http.Response) any {
	if response == nil {
		return nil
	}
	return response.StatusCode
}
