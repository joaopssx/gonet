package tcp

import (
	"errors"
	"fmt"

	"go.uber.org/zap"
)

var (
	// ErrUnexpectedSegment is returned when a handshake handler receives a
	// segment whose flags do not match the expected step.
	ErrUnexpectedSegment = errors.New("unexpected segment for handshake step")
	// ErrBadAck is returned when an acknowledgment number does not match what
	// we expect for the connection.
	ErrBadAck = errors.New("acknowledgment number does not match")
)

// sendSYN initiates an active open (client side): CLOSED -> SYN_SENT.
func (c *TCPConn) sendSYN() error {
	c.sndISN = GenerateISN()
	c.sndUNA = c.sndISN
	c.sndNXT = c.sndISN + 1 // SYN consumes one sequence number

	h := c.newHeader(FlagSYN)
	h.SeqNum = c.sndISN
	h.Options = []TCPOption{mssOption(c.mss)}

	if err := c.send(h, nil); err != nil {
		return fmt.Errorf("send SYN: %w", err)
	}

	c.log.Debug("sent SYN", zap.Uint32("isn", c.sndISN))
	return c.state.Transition(StateSynSent)
}

// sendSYNACK responds to an incoming SYN (server side). It assumes rcvNXT has
// already been set to the peer's ISN+1 by handleSYN.
func (c *TCPConn) sendSYNACK(theirSYN *Header) error {
	c.sndISN = GenerateISN()
	c.sndUNA = c.sndISN
	c.sndNXT = c.sndISN + 1 // SYN consumes one sequence number

	h := c.newHeader(FlagSYN | FlagACK)
	h.SeqNum = c.sndISN
	h.AckNum = c.rcvNXT
	h.Options = []TCPOption{mssOption(c.mss)}

	if err := c.send(h, nil); err != nil {
		return fmt.Errorf("send SYN-ACK: %w", err)
	}

	c.log.Debug("sent SYN-ACK", zap.Uint32("isn", c.sndISN), zap.Uint32("ack", c.rcvNXT))
	return nil
}

// handleSYN processes an incoming SYN on the passive (server) side and replies
// with a SYN-ACK: LISTEN -> SYN_RECEIVED.
func (c *TCPConn) handleSYN(seg *Header) error {
	if !seg.HasFlag(FlagSYN) {
		return ErrUnexpectedSegment
	}

	// A passive connection may be created directly in CLOSED; move it to LISTEN
	// so the LISTEN -> SYN_RECEIVED transition is valid.
	if c.state.Is(StateClosed) {
		if err := c.state.Transition(StateListen); err != nil {
			return err
		}
	}

	c.rcvNXT = seg.SeqNum + 1 // SYN consumes one sequence number
	c.sndWND = seg.Window
	c.negotiateMSS(seg)

	if err := c.sendSYNACK(seg); err != nil {
		return err
	}

	return c.state.Transition(StateSynReceived)
}

// handleSYNACK processes the SYN-ACK on the active (client) side, sends the
// final ACK, and completes the handshake: SYN_SENT -> ESTABLISHED.
func (c *TCPConn) handleSYNACK(seg *Header) error {
	if !seg.HasFlag(FlagSYN) || !seg.HasFlag(FlagACK) {
		return ErrUnexpectedSegment
	}
	// The peer must acknowledge our SYN (ISN_c + 1 == sndNXT).
	if seg.AckNum != c.sndNXT {
		return ErrBadAck
	}

	c.sndUNA = seg.AckNum
	c.rcvNXT = seg.SeqNum + 1 // their SYN consumes one sequence number
	c.sndWND = seg.Window
	c.negotiateMSS(seg)

	if err := c.sendACK(); err != nil {
		return err
	}

	c.log.Debug("handshake complete (client)", zap.Uint32("rcv_nxt", c.rcvNXT))
	return c.state.Transition(StateEstablished)
}

// handleACKInSynReceived processes the final ACK of the handshake on the server
// side: SYN_RECEIVED -> ESTABLISHED.
func (c *TCPConn) handleACKInSynReceived(seg *Header) error {
	if !seg.HasFlag(FlagACK) {
		return ErrUnexpectedSegment
	}
	if seg.AckNum != c.sndNXT {
		return ErrBadAck
	}

	c.sndUNA = seg.AckNum
	c.sndWND = seg.Window

	c.log.Debug("handshake complete (server)", zap.Uint32("snd_una", c.sndUNA))
	return c.state.Transition(StateEstablished)
}
