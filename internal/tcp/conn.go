package tcp

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"time"

	"go.uber.org/zap"
)

// Default connection parameters.
const (
	// DefaultMSS is the maximum segment size advertised by default (Ethernet MTU 1500 - 20 IP - 20 TCP).
	DefaultMSS uint16 = 1460
	// DefaultWindow is the default receive window advertised.
	DefaultWindow uint16 = 65535
)

// TCPConn represents a single TCP connection and its transmission control block (TCB).
//
// The send/receive sequence variables follow the naming from RFC 793:
//
//	sndUNA: oldest unacknowledged sequence number
//	sndNXT: next sequence number to be sent
//	rcvNXT: next sequence number expected from the peer
type TCPConn struct {
	key   ConnKey
	state *StateMachine

	sndISN uint32 // initial send sequence number
	sndNXT uint32 // send next
	sndUNA uint32 // send unacknowledged
	sndWND uint16 // send window (peer's advertised receive window)

	rcvNXT uint32 // receive next
	rcvWND uint16 // receive window we advertise

	mss    uint16
	output func([]byte) error
	log    *zap.Logger
}

// NewTCPConn creates a new TCP connection in the CLOSED state.
func NewTCPConn(key ConnKey, output func([]byte) error, log *zap.Logger) *TCPConn {
	if log == nil {
		log = zap.NewNop()
	}
	return &TCPConn{
		key:    key,
		state:  NewStateMachine(StateClosed, log),
		mss:    DefaultMSS,
		rcvWND: DefaultWindow,
		sndWND: DefaultWindow,
		output: output,
		log:    log,
	}
}

// State returns the current connection state.
func (c *TCPConn) State() State {
	return c.state.Current()
}

// GenerateISN generates an Initial Sequence Number combining a cryptographically
// random value with the current monotonic time, loosely following RFC 6528.
func GenerateISN() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Fall back to time-only if the system RNG is unavailable.
		return uint32(time.Now().UnixNano())
	}
	return binary.BigEndian.Uint32(b[:]) + uint32(time.Now().UnixNano())
}

// checksumCalc returns a checksum calculator bound to this connection's IP pair.
func (c *TCPConn) checksumCalc() *ChecksumCalculator {
	return NewChecksumCalculator(net.IP(c.key.SrcIP[:]), net.IP(c.key.DstIP[:]))
}

// send marshals the header (plus optional payload), fills in the checksum, and
// dispatches the segment through the connection's output function.
func (c *TCPConn) send(h *Header, payload []byte) error {
	segment, err := h.Marshal()
	if err != nil {
		return err
	}
	if len(payload) > 0 {
		segment = append(segment, payload...)
	}
	c.checksumCalc().SetAndCompute(segment)
	return c.output(segment)
}

// newHeader builds a header pre-filled with this connection's ports and window.
func (c *TCPConn) newHeader(flags uint8) *Header {
	return &Header{
		SrcPort: c.key.SrcPort,
		DstPort: c.key.DstPort,
		Flags:   flags,
		Window:  c.rcvWND,
	}
}

// sendACK sends a bare ACK segment acknowledging everything received so far.
func (c *TCPConn) sendACK() error {
	h := c.newHeader(FlagACK)
	h.SeqNum = c.sndNXT
	h.AckNum = c.rcvNXT
	return c.send(h, nil)
}

// mssOption returns an MSS TCP option carrying the given value.
func mssOption(mss uint16) TCPOption {
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, mss)
	return TCPOption{Kind: OptMSS, Length: 4, Data: data}
}

// parseMSS extracts the MSS value advertised in a header's options, if present.
func parseMSS(h *Header) (uint16, bool) {
	for _, opt := range h.Options {
		if opt.Kind == OptMSS && len(opt.Data) == 2 {
			return binary.BigEndian.Uint16(opt.Data), true
		}
	}
	return 0, false
}

// negotiateMSS lowers our MSS to the peer's if it advertised a smaller one.
func (c *TCPConn) negotiateMSS(seg *Header) {
	if peerMSS, ok := parseMSS(seg); ok && peerMSS > 0 && peerMSS < c.mss {
		c.mss = peerMSS
	}
}
