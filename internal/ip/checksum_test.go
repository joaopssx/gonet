package ip

import (
	"net"
	"testing"
)

func TestChecksumKnownValue(t *testing.T) {
	raw := []byte{
		0x45, 0x00, 0x00, 0x54, 0x12, 0x34, 0x40, 0x00, 0x40, 0x01, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01, 0x08, 0x08, 0x08, 0x08,
	}
	sum := Checksum(raw)

	raw[10] = byte(sum >> 8)
	raw[11] = byte(sum)

	if !VerifyChecksum(raw) {
		t.Errorf("calculated checksum %04x did not verify", sum)
	}
}

func TestVerifyChecksum(t *testing.T) {
	raw := []byte{
		0x45, 0x00, 0x00, 0x54, 0x12, 0x34, 0x40, 0x00, 0x40, 0x01, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01, 0x08, 0x08, 0x08, 0x08,
	}
	sum := Checksum(raw)
	raw[10] = byte(sum >> 8)
	raw[11] = byte(sum)

	if !VerifyChecksum(raw) {
		t.Errorf("expected VerifyChecksum to be true")
	}

	raw[12]++
	if VerifyChecksum(raw) {
		t.Errorf("expected VerifyChecksum to be false after corruption")
	}
}

func TestTCPChecksumPseudoHeader(t *testing.T) {
	src := net.ParseIP("192.168.1.1").To4()
	dst := net.ParseIP("8.8.8.8").To4()

	tcpSeg := []byte{
		0x04, 0xd2, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x50, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	sum := TCPChecksum(src, dst, tcpSeg)
	tcpSeg[16] = byte(sum >> 8)
	tcpSeg[17] = byte(sum)

	verifySum := TCPChecksum(src, dst, tcpSeg)
	if verifySum != 0 {
		t.Errorf("expected TCP checksum to verify to 0, got %04x", verifySum)
	}
}
