//go:build linux

package tun

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

type mockPacketIO struct {
	io.Reader
	io.Writer
}

func (m *mockPacketIO) Close() error { return nil }
func (m *mockPacketIO) Name() string  { return "mock" }

type mockHandler struct {
	mu      sync.Mutex
	packets [][]byte
	called  chan struct{}
}

func (h *mockHandler) HandlePacket(raw []byte) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.packets = append(h.packets, raw)
	select {
	case h.called <- struct{}{}:
	default:
	}
	return nil
}

func TestReadLoopStartStop(t *testing.T) {
	r, _ := io.Pipe() // pipe reader blocks until write
	mockIO := &mockPacketIO{Reader: r}
	handler := &mockHandler{}
	log := zap.NewNop()

	loop := NewReadLoop(mockIO, handler, 1500, log)
	ctx := context.Background()

	err := loop.Start(ctx)
	if err != nil {
		t.Fatalf("unexpected start error: %v", err)
	}

	err = loop.Stop()
	if err != nil {
		t.Fatalf("unexpected stop error: %v", err)
	}
}

func TestReadLoopHandlerCalled(t *testing.T) {
	r, w := io.Pipe()
	mockIO := &mockPacketIO{Reader: r}
	handler := &mockHandler{called: make(chan struct{}, 1)}
	log := zap.NewNop()

	loop := NewReadLoop(mockIO, handler, 1500, log)
	loop.Start(context.Background())

	msg := []byte("hello network")
	go func() {
		w.Write(msg)
	}()

	select {
	case <-handler.called:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for handler to be called")
	}

	loop.Stop()

	handler.mu.Lock()
	defer handler.mu.Unlock()
	if len(handler.packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(handler.packets))
	}
	if string(handler.packets[0]) != string(msg) {
		t.Fatalf("expected %q, got %q", string(msg), string(handler.packets[0]))
	}
}

func TestReadLoopGracefulShutdown(t *testing.T) {
	r, _ := io.Pipe()
	mockIO := &mockPacketIO{Reader: r}
	handler := &mockHandler{}
	log := zap.NewNop()

	loop := NewReadLoop(mockIO, handler, 1500, log)
	ctx, cancel := context.WithCancel(context.Background())
	loop.Start(ctx)

	// Trigger shutdown via context cancellation
	cancel()

	done := make(chan struct{})
	go func() {
		// Stop should return quickly since context is canceled
		if err := loop.Stop(); err != nil {
			t.Errorf("Stop returned error: %v", err)
		}
		close(done)
	}()

	select {
	case <-done:
		// success
	case <-time.After(1 * time.Second):
		t.Fatal("graceful shutdown took too long")
	}
}
