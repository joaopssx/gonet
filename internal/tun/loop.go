//go:build linux

package tun

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"go.uber.org/zap"
)

// PacketHandler defines the interface for processing incoming raw IP packets.
type PacketHandler interface {
	HandlePacket(raw []byte) error
}

// LoopStats holds statistics about the read loop.
type LoopStats struct {
	PacketsRead uint64
	BytesRead   uint64
	Errors      uint64
}

// ReadLoop is responsible for continuously reading packets from a PacketIO interface
// and dispatching them to a PacketHandler.
type ReadLoop struct {
	io      PacketIO
	handler PacketHandler
	bufSize int
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	log     *zap.Logger

	packetsRead atomic.Uint64
	bytesRead   atomic.Uint64
	readErrors  atomic.Uint64
}

// NewReadLoop creates a new ReadLoop instance.
func NewReadLoop(io PacketIO, handler PacketHandler, bufSize int, log *zap.Logger) *ReadLoop {
	return &ReadLoop{
		io:      io,
		handler: handler,
		bufSize: bufSize,
		log:     log,
	}
}

// Start begins the packet reading loop in a new background goroutine.
func (r *ReadLoop) Start(ctx context.Context) error {
	r.ctx, r.cancel = context.WithCancel(ctx)
	r.wg.Add(1)

	go r.loop()
	return nil
}

func (r *ReadLoop) loop() {
	defer r.wg.Done()
	r.log.Info("starting read loop", zap.String("interface", r.io.Name()))

	for {
		// Check for cancellation before reading
		select {
		case <-r.ctx.Done():
			r.log.Info("stopping read loop due to context cancellation")
			return
		default:
		}

		buf := make([]byte, r.bufSize)
		n, err := r.io.Read(buf)
		if err != nil {
			// Check for transient errors like EINTR
			if errors.Is(err, syscall.EINTR) {
				continue
			}

			// If context is canceled while blocked on read (e.g. io.Close() unblocked it), gracefully exit
			select {
			case <-r.ctx.Done():
				r.log.Info("read loop ending cleanly after cancellation")
				return
			default:
			}

			r.readErrors.Add(1)
			r.log.Error("fatal error reading from tun interface", zap.Error(err))
			return
		}

		r.packetsRead.Add(1)
		r.bytesRead.Add(uint64(n))

		// Process packet in a separate goroutine to avoid blocking the read loop
		// We copy the buffer to avoid data races and retain only the valid bytes
		packet := make([]byte, n)
		copy(packet, buf[:n])

		go func(pkt []byte) {
			if err := r.handler.HandlePacket(pkt); err != nil {
				r.log.Warn("failed to handle packet", zap.Error(err))
			}
		}(packet)
	}
}

// Stop gracefully signals the read loop to shut down and waits up to 5 seconds for it to finish.
func (r *ReadLoop) Stop() error {
	if r.cancel != nil {
		r.cancel() // signal loop to stop
	}

	done := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		r.log.Info("read loop stopped gracefully")
		return nil
	case <-time.After(5 * time.Second):
		r.log.Warn("timeout waiting for read loop to stop")
		return errors.New("timeout waiting for read loop to stop")
	}
}

// Stats returns the current statistics of the read loop.
func (r *ReadLoop) Stats() LoopStats {
	return LoopStats{
		PacketsRead: r.packetsRead.Load(),
		BytesRead:   r.bytesRead.Load(),
		Errors:      r.readErrors.Load(),
	}
}
