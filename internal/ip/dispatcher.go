package ip

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"

	"go.uber.org/zap"
)

// DispatchStats holds statistics for the IP dispatcher.
type DispatchStats struct {
	PacketsReceived   uint64
	PacketsInvalid    uint64
	PacketsDropped    uint64
	PacketsDispatched uint64
}

// ProtocolHandler defines an interface for handling a specific IP protocol payload.
// For example: TCP (6), UDP (17), ICMP (1).
type ProtocolHandler interface {
	Protocol() uint8
	HandleIPPayload(srcIP, dstIP net.IP, payload []byte) error
}

// Dispatcher routes incoming IP packets to the appropriate ProtocolHandler
// based on the Protocol field in the IPv4 header.
type Dispatcher struct {
	handlers map[uint8]ProtocolHandler
	mu       sync.RWMutex
	log      *zap.Logger

	packetsReceived   atomic.Uint64
	packetsInvalid    atomic.Uint64
	packetsDropped    atomic.Uint64
	packetsDispatched atomic.Uint64
}

// NewDispatcher creates a new IP packet dispatcher.
func NewDispatcher(log *zap.Logger) *Dispatcher {
	return &Dispatcher{
		handlers: make(map[uint8]ProtocolHandler),
		log:      log,
	}
}

// Register adds a ProtocolHandler to the dispatcher.
func (d *Dispatcher) Register(h ProtocolHandler) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.handlers[h.Protocol()] = h
}

// HandlePacket fulfills the tun.PacketHandler interface required by the read loop.
func (d *Dispatcher) HandlePacket(raw []byte) error {
	return d.Dispatch(raw)
}

// Dispatch parses the IPv4 header manually and routes the payload to a registered handler.
func (d *Dispatcher) Dispatch(raw []byte) error {
	d.packetsReceived.Add(1)

	// An IPv4 header without options is at least 20 bytes long
	if len(raw) < 20 {
		d.packetsInvalid.Add(1)
		d.log.Warn("packet too short to contain IPv4 header", zap.Int("len", len(raw)))
		return errors.New("packet too short")
	}

	// The first byte contains Version (high 4 bits) and IHL (low 4 bits)
	version := raw[0] >> 4
	if version != 4 {
		d.packetsInvalid.Add(1)
		d.log.Warn("invalid IP version", zap.Uint8("version", version))
		return errors.New("invalid IP version, expected IPv4")
	}

	ihl := raw[0] & 0x0F
	headerLen := int(ihl) * 4
	if headerLen < 20 || headerLen > len(raw) {
		d.packetsInvalid.Add(1)
		d.log.Warn("invalid IPv4 header length", zap.Int("ihl", int(ihl)))
		return errors.New("invalid IPv4 header length")
	}

	// Total Length is a 16-bit field at offset 2
	totalLen := int(raw[2])<<8 | int(raw[3])
	if totalLen > len(raw) || totalLen < headerLen {
		d.packetsInvalid.Add(1)
		d.log.Warn("invalid IPv4 total length", zap.Int("total_len", totalLen), zap.Int("packet_len", len(raw)))
		return errors.New("invalid IPv4 total length")
	}

	// Truncate raw slice to the packet's total length (ignore ethernet padding if present)
	packet := raw[:totalLen]

	// Extract Protocol, Source IP, and Destination IP
	protocol := packet[9]
	srcIP := net.IPv4(packet[12], packet[13], packet[14], packet[15])
	dstIP := net.IPv4(packet[16], packet[17], packet[18], packet[19])

	// Extract the payload
	payload := packet[headerLen:]

	// Find the handler for this protocol
	d.mu.RLock()
	handler, ok := d.handlers[protocol]
	d.mu.RUnlock()

	if !ok {
		d.packetsDropped.Add(1)
		d.log.Debug("no handler for IP protocol, dropping packet", zap.Uint8("protocol", protocol))
		return nil
	}

	d.packetsDispatched.Add(1)
	return handler.HandleIPPayload(srcIP, dstIP, payload)
}

// Stats returns the current dispatcher statistics.
func (d *Dispatcher) Stats() DispatchStats {
	return DispatchStats{
		PacketsReceived:   d.packetsReceived.Load(),
		PacketsInvalid:    d.packetsInvalid.Load(),
		PacketsDropped:    d.packetsDropped.Load(),
		PacketsDispatched: d.packetsDispatched.Load(),
	}
}
