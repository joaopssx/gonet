package tcp

import (
	"testing"

	"go.uber.org/zap/zaptest"
)

// capturer collects segments emitted by a connection so the test can deliver
// them to the peer one step at a time (modeling an asynchronous wire rather
// than a reentrant synchronous cascade).
type capturer struct {
	segments [][]byte
}

func (c *capturer) out(seg []byte) error {
	cp := make([]byte, len(seg))
	copy(cp, seg)
	c.segments = append(c.segments, cp)
	return nil
}

func (c *capturer) pop(t *testing.T) *Header {
	t.Helper()
	if len(c.segments) == 0 {
		t.Fatal("expected a segment to have been sent, got none")
	}
	seg := c.segments[0]
	c.segments = c.segments[1:]
	h, err := ParseHeader(seg)
	if err != nil {
		t.Fatalf("failed to parse emitted segment: %v", err)
	}
	return h
}

func TestThreeWayHandshake(t *testing.T) {
	log := zaptest.NewLogger(t)

	clientOut := &capturer{}
	serverOut := &capturer{}

	clientKey := ConnKey{SrcIP: [4]byte{10, 0, 0, 1}, SrcPort: 50000, DstIP: [4]byte{10, 0, 0, 2}, DstPort: 80}
	serverKey := ConnKey{SrcIP: [4]byte{10, 0, 0, 2}, SrcPort: 80, DstIP: [4]byte{10, 0, 0, 1}, DstPort: 50000}

	client := NewTCPConn(clientKey, clientOut.out, log)
	server := NewTCPConn(serverKey, serverOut.out, log)

	// Step 1: client sends SYN, enters SYN_SENT.
	if err := client.sendSYN(); err != nil {
		t.Fatalf("sendSYN failed: %v", err)
	}
	if !client.state.Is(StateSynSent) {
		t.Fatalf("client expected SYN_SENT, got %s", client.State())
	}
	syn := clientOut.pop(t)
	if !syn.HasFlag(FlagSYN) || syn.HasFlag(FlagACK) {
		t.Fatalf("expected pure SYN, got %s", syn)
	}

	// Step 2: server receives SYN, replies SYN-ACK, enters SYN_RECEIVED.
	if err := server.handleSYN(syn); err != nil {
		t.Fatalf("handleSYN failed: %v", err)
	}
	if !server.state.Is(StateSynReceived) {
		t.Fatalf("server expected SYN_RECEIVED, got %s", server.State())
	}
	synack := serverOut.pop(t)
	if !synack.HasFlag(FlagSYN) || !synack.HasFlag(FlagACK) {
		t.Fatalf("expected SYN-ACK, got %s", synack)
	}
	if synack.AckNum != client.sndISN+1 {
		t.Errorf("SYN-ACK ack=%d, want %d", synack.AckNum, client.sndISN+1)
	}

	// Step 3: client receives SYN-ACK, replies ACK, enters ESTABLISHED.
	if err := client.handleSYNACK(synack); err != nil {
		t.Fatalf("handleSYNACK failed: %v", err)
	}
	if !client.state.Is(StateEstablished) {
		t.Fatalf("client expected ESTABLISHED, got %s", client.State())
	}
	ack := clientOut.pop(t)
	if !ack.HasFlag(FlagACK) || ack.HasFlag(FlagSYN) {
		t.Fatalf("expected pure ACK, got %s", ack)
	}

	// Step 4: server receives final ACK, enters ESTABLISHED.
	if err := server.handleACKInSynReceived(ack); err != nil {
		t.Fatalf("handleACKInSynReceived failed: %v", err)
	}
	if !server.state.Is(StateEstablished) {
		t.Fatalf("server expected ESTABLISHED, got %s", server.State())
	}

	// Sequence bookkeeping: each side's rcvNXT must equal the peer's ISN+1.
	if client.rcvNXT != server.sndISN+1 {
		t.Errorf("client.rcvNXT=%d, want server ISN+1=%d", client.rcvNXT, server.sndISN+1)
	}
	if server.rcvNXT != client.sndISN+1 {
		t.Errorf("server.rcvNXT=%d, want client ISN+1=%d", server.rcvNXT, client.sndISN+1)
	}
	if client.sndUNA != client.sndNXT {
		t.Errorf("client SYN unacknowledged: sndUNA=%d sndNXT=%d", client.sndUNA, client.sndNXT)
	}
	if server.sndUNA != server.sndNXT {
		t.Errorf("server SYN unacknowledged: sndUNA=%d sndNXT=%d", server.sndUNA, server.sndNXT)
	}
}

func TestHandshakeRejectsBadAck(t *testing.T) {
	log := zaptest.NewLogger(t)
	key := ConnKey{SrcIP: [4]byte{10, 0, 0, 1}, SrcPort: 50000, DstIP: [4]byte{10, 0, 0, 2}, DstPort: 80}

	c := NewTCPConn(key, func([]byte) error { return nil }, log)
	if err := c.sendSYN(); err != nil {
		t.Fatalf("sendSYN failed: %v", err)
	}

	// A SYN-ACK acknowledging the wrong sequence number must be rejected.
	bad := &Header{Flags: FlagSYN | FlagACK, SeqNum: 999, AckNum: c.sndNXT + 100}
	if err := c.handleSYNACK(bad); err != ErrBadAck {
		t.Errorf("expected ErrBadAck, got %v", err)
	}
	if c.state.Is(StateEstablished) {
		t.Errorf("connection must not be ESTABLISHED after bad ACK")
	}
}

func TestMSSNegotiation(t *testing.T) {
	log := zaptest.NewLogger(t)
	serverKey := ConnKey{SrcIP: [4]byte{10, 0, 0, 2}, SrcPort: 80, DstIP: [4]byte{10, 0, 0, 1}, DstPort: 50000}
	server := NewTCPConn(serverKey, func([]byte) error { return nil }, log)

	// Incoming SYN advertising a smaller MSS than our default.
	syn := &Header{Flags: FlagSYN, SeqNum: 100, Options: []TCPOption{mssOption(1400)}}
	if err := server.handleSYN(syn); err != nil {
		t.Fatalf("handleSYN failed: %v", err)
	}
	if server.mss != 1400 {
		t.Errorf("expected negotiated MSS 1400, got %d", server.mss)
	}
}
