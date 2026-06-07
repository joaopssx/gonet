package ip

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestReassemblyInOrder(t *testing.T) {
	builder := NewPacketBuilder(net.IPv4(1, 2, 3, 4), net.IPv4(5, 6, 7, 8), ProtoICMP)
	payload := make([]byte, 2000)
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	packet, _ := builder.Build(payload)

	frags, _ := Fragment(packet, 1000)

	var reassembled []byte
	buf := NewReassemblyBuffer(func(res []byte) {
		reassembled = res
	}, nil)

	for _, f := range frags {
		buf.Add(f)
	}

	if reassembled == nil {
		t.Fatalf("expected reassembly to complete")
	}

	if !bytes.Equal(packet, reassembled) {
		t.Errorf("reassembled packet does not match original")
	}
}

func TestReassemblyOutOfOrder(t *testing.T) {
	builder := NewPacketBuilder(net.IPv4(1, 2, 3, 4), net.IPv4(5, 6, 7, 8), ProtoICMP)
	payload := make([]byte, 3000)
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	packet, _ := builder.Build(payload)

	frags, _ := Fragment(packet, 1000)

	var reassembled []byte
	buf := NewReassemblyBuffer(func(res []byte) {
		reassembled = res
	}, nil)

	for i := len(frags) - 1; i >= 0; i-- {
		buf.Add(frags[i])
	}

	if reassembled == nil {
		t.Fatalf("expected reassembly to complete")
	}

	if !bytes.Equal(packet, reassembled) {
		t.Errorf("reassembled packet does not match original")
	}
}

func TestReassemblyTimeout(t *testing.T) {
	builder := NewPacketBuilder(net.IPv4(1, 2, 3, 4), net.IPv4(5, 6, 7, 8), ProtoICMP)
	payload := make([]byte, 3000)
	packet, _ := builder.Build(payload)

	frags, _ := Fragment(packet, 1000)

	buf := NewReassemblyBuffer(func(res []byte) {}, nil)

	buf.Add(frags[0])
	if buf.Stats().GroupsActive != 1 {
		t.Fatalf("expected 1 active group")
	}

	// Trigger manual cleanup bypassing ticker, simulating 31 seconds in the future
	buf.cleanup(time.Now().Add(31 * time.Second))

	if buf.Stats().GroupsActive != 0 {
		t.Fatalf("expected group to be evicted, got %d", buf.Stats().GroupsActive)
	}
}
