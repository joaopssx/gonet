package ip

import (
	"bytes"
	"net"
	"testing"

	"go.uber.org/zap"
)

type mockProtoHandler struct {
	proto       uint8
	called      int
	lastSrc     net.IP
	lastDst     net.IP
	lastPayload []byte
}

func (m *mockProtoHandler) Protocol() uint8 { return m.proto }
func (m *mockProtoHandler) HandleIPPayload(srcIP, dstIP net.IP, payload []byte) error {
	m.called++
	m.lastSrc = srcIP
	m.lastDst = dstIP
	m.lastPayload = payload
	return nil
}

func TestDispatchUnknownProtocol(t *testing.T) {
	d := NewDispatcher(zap.NewNop())

	// Build a valid basic IP packet with an unknown protocol (254)
	packet := make([]byte, 20)
	packet[0] = 0x45 // version 4, IHL 5 (20 bytes)
	packet[2] = 0x00
	packet[3] = 0x14 // total length 20
	packet[9] = 254  // protocol 254

	err := d.Dispatch(packet)
	if err != nil {
		t.Fatalf("expected nil error for unknown protocol, got: %v", err)
	}
}

func TestDispatchInvalidPacket(t *testing.T) {
	d := NewDispatcher(zap.NewNop())

	packet := make([]byte, 10) // too short
	err := d.Dispatch(packet)
	if err == nil {
		t.Fatal("expected error for short packet, got nil")
	}
}

func TestDispatchRouting(t *testing.T) {
	d := NewDispatcher(zap.NewNop())

	tcpHandler := &mockProtoHandler{proto: 6}
	udpHandler := &mockProtoHandler{proto: 17}

	d.Register(tcpHandler)
	d.Register(udpHandler)

	// Create a mock TCP packet
	tcpPkt := make([]byte, 24)
	tcpPkt[0] = 0x45
	tcpPkt[2] = 0x00
	tcpPkt[3] = 0x18 // Total length 24
	tcpPkt[9] = 6    // TCP protocol
	tcpPkt[12] = 192
	tcpPkt[13] = 168
	tcpPkt[14] = 1
	tcpPkt[15] = 1 // Src IP
	tcpPkt[16] = 10
	tcpPkt[17] = 0
	tcpPkt[18] = 0
	tcpPkt[19] = 1 // Dst IP
	copy(tcpPkt[20:], []byte("DATA"))

	if err := d.Dispatch(tcpPkt); err != nil {
		t.Fatalf("unexpected dispatch error: %v", err)
	}

	if tcpHandler.called != 1 {
		t.Errorf("expected tcp handler to be called once, got %d", tcpHandler.called)
	}
	if udpHandler.called != 0 {
		t.Errorf("expected udp handler to not be called, got %d", udpHandler.called)
	}
	if !bytes.Equal(tcpHandler.lastPayload, []byte("DATA")) {
		t.Errorf("expected payload DATA, got %s", string(tcpHandler.lastPayload))
	}

	// Create a mock UDP packet
	udpPkt := make([]byte, 22)
	udpPkt[0] = 0x45
	udpPkt[2] = 0x00
	udpPkt[3] = 0x16 // Total length 22
	udpPkt[9] = 17   // UDP protocol

	if err := d.Dispatch(udpPkt); err != nil {
		t.Fatalf("unexpected dispatch error: %v", err)
	}

	if udpHandler.called != 1 {
		t.Errorf("expected udp handler to be called once, got %d", udpHandler.called)
	}
	if tcpHandler.called != 1 { // Should remain 1 from previous call
		t.Errorf("expected tcp handler to be called once, got %d", tcpHandler.called)
	}
}
