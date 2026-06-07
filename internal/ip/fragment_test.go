package ip

import (
	"net"
	"testing"
)

func TestFragmentFitsInMTU(t *testing.T) {
	builder := NewPacketBuilder(net.IPv4(1, 2, 3, 4), net.IPv4(5, 6, 7, 8), ProtoICMP)
	payload := make([]byte, 100)
	packet, _ := builder.Build(payload)

	frags, err := Fragment(packet, 1500)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(frags) != 1 {
		t.Fatalf("expected 1 fragment, got %d", len(frags))
	}
}

func TestFragmentSplit(t *testing.T) {
	builder := NewPacketBuilder(net.IPv4(1, 2, 3, 4), net.IPv4(5, 6, 7, 8), ProtoICMP)
	payload := make([]byte, 2960) // 2960 payload + 20 header = 2980 total.
	packet, _ := builder.Build(payload)

	frags, err := Fragment(packet, 1500)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// MTU 1500 -> 1480 max payload per fragment. 2960 / 1480 = exactly 2 fragments.
	if len(frags) != 2 {
		t.Fatalf("expected 2 fragments, got %d", len(frags))
	}

	h1, _ := ParseHeader(frags[0])
	h2, _ := ParseHeader(frags[1])

	if h1.Flags&FlagMF == 0 {
		t.Errorf("expected first fragment to have MF flag set")
	}
	if h2.Flags&FlagMF != 0 {
		t.Errorf("expected second fragment to not have MF flag set")
	}
}

func TestFragmentOffsets(t *testing.T) {
	builder := NewPacketBuilder(net.IPv4(1, 2, 3, 4), net.IPv4(5, 6, 7, 8), ProtoICMP)
	payload := make([]byte, 2000)
	packet, _ := builder.Build(payload)

	frags, _ := Fragment(packet, 1000)

	h0, _ := ParseHeader(frags[0])
	if h0.FragOffset != 0 {
		t.Errorf("expected frag 0 offset 0, got %d", h0.FragOffset)
	}

	h1, _ := ParseHeader(frags[1])
	if h1.FragOffset != 976/8 {
		t.Errorf("expected frag 1 offset 122, got %d", h1.FragOffset)
	}
}
