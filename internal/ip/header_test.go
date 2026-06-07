package ip

import (
	"bytes"
	"net"
	"testing"
)

func TestParseRealPacket(t *testing.T) {
	// Simple IPv4 ICMP Echo Request (ping 8.8.8.8)
	raw := []byte{
		0x45, 0x00, 0x00, 0x54, 0x12, 0x34, 0x40, 0x00, 0x40, 0x01, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01, 0x08, 0x08, 0x08, 0x08,
	}

	sum := Checksum(raw[:20])
	raw[10] = byte(sum >> 8)
	raw[11] = byte(sum)

	header, err := ParseHeader(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if header.Version != 4 {
		t.Errorf("expected version 4, got %d", header.Version)
	}
	if header.IHL != 5 {
		t.Errorf("expected IHL 5, got %d", header.IHL)
	}
	if header.TotalLen != 84 {
		t.Errorf("expected TotalLen 84, got %d", header.TotalLen)
	}
	if header.ID != 0x1234 {
		t.Errorf("expected ID 0x1234, got %04x", header.ID)
	}
	if header.Flags != FlagDF {
		t.Errorf("expected FlagDF (0x02), got %02x", header.Flags)
	}
	if header.Protocol != ProtoICMP {
		t.Errorf("expected Protocol 1, got %d", header.Protocol)
	}
	if !header.Src.Equal(net.IPv4(192, 168, 1, 1)) {
		t.Errorf("expected Src 192.168.1.1, got %s", header.Src)
	}
	if !header.Dst.Equal(net.IPv4(8, 8, 8, 8)) {
		t.Errorf("expected Dst 8.8.8.8, got %s", header.Dst)
	}
}

func TestMarshalRoundtrip(t *testing.T) {
	raw := []byte{
		0x45, 0x00, 0x00, 0x54, 0x12, 0x34, 0x40, 0x00, 0x40, 0x01, 0x11, 0x11, 0xc0, 0xa8, 0x01, 0x01, 0x08, 0x08, 0x08, 0x08,
	}
	header, err := ParseHeader(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out, err := header.Marshal()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !bytes.Equal(raw, out) {
		t.Errorf("roundtrip failed:\nexpected: %x\ngot:      %x", raw, out)
	}
}

func TestHeaderLen(t *testing.T) {
	raw5 := []byte{
		0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	h5, _ := ParseHeader(raw5)
	if h5.HeaderLen() != 20 {
		t.Errorf("expected 20, got %d", h5.HeaderLen())
	}

	raw6 := []byte{
		0x46, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x02, 0x03, 0x04,
	}
	h6, _ := ParseHeader(raw6)
	if h6.HeaderLen() != 24 {
		t.Errorf("expected 24, got %d", h6.HeaderLen())
	}
}
