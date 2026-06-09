package tcp

import (
	"bytes"
	"net"
	"testing"
)

func TestChecksumCalculator(t *testing.T) {
	// A valid TCP SYN segment with its pseudo-header components
	src := net.ParseIP("10.0.0.1").To4()
	dst := net.ParseIP("10.0.0.2").To4()

	// Constructed TCP SYN segment
	// TCP Header sum:
	// 04d2 + 0050 = 0522
	// 0000 + 0001 = 0001
	// 0000 + 0000 = 0000
	// 5002 + 0400 = 5402
	// 0000 (chk) + 0000 (urg) = 0000
	// TCP Sum = 0522 + 0001 + 5402 = 5925
	//
	// Pseudo-header sum:
	// Src: 0a00 + 0001 = 0a01
	// Dst: 0a00 + 0002 = 0a02
	// Reserved+Proto: 0006
	// Len: 0014 (20)
	// PH Sum = 0a01 + 0a02 + 0006 + 0014 = 141d
	// Total sum: 141d + 5925 = 6d42.
	// Complement: ^6d42 = 92bd.
	expectedChecksum := uint16(0x92bd)

	tcpSegment := []byte{
		0x04, 0xd2, 0x00, 0x50, // SrcPort: 1234, DstPort: 80
		0x00, 0x00, 0x00, 0x01, // SeqNum: 1
		0x00, 0x00, 0x00, 0x00, // AckNum: 0
		0x50, 0x02, 0x04, 0x00, // DataOffset: 5, Flags: SYN, Window: 1024
		0x92, 0xbd, 0x00, 0x00, // Checksum: 0x92bd, Urgent: 0
	}

	calc := NewChecksumCalculator(src, dst)

	t.Run("Verify valid checksum", func(t *testing.T) {
		if !calc.Verify(tcpSegment) {
			t.Errorf("expected checksum verification to pass")
		}
	})

	t.Run("Verify invalid checksum", func(t *testing.T) {
		invalidSegment := make([]byte, len(tcpSegment))
		copy(invalidSegment, tcpSegment)
		invalidSegment[15] = 0xff // Change window size to invalidate checksum
		if calc.Verify(invalidSegment) {
			t.Errorf("expected checksum verification to fail")
		}
	})

	t.Run("Compute checksum", func(t *testing.T) {
		zeroChecksumSegment := make([]byte, len(tcpSegment))
		copy(zeroChecksumSegment, tcpSegment)
		zeroChecksumSegment[16] = 0
		zeroChecksumSegment[17] = 0

		computed := calc.Compute(zeroChecksumSegment)
		if computed != expectedChecksum {
			t.Errorf("expected computed checksum 0x%04x, got 0x%04x", expectedChecksum, computed)
		}
	})

	t.Run("SetAndCompute", func(t *testing.T) {
		brokenChecksumSegment := make([]byte, len(tcpSegment))
		copy(brokenChecksumSegment, tcpSegment)
		brokenChecksumSegment[16] = 0xff
		brokenChecksumSegment[17] = 0xff

		modified := calc.SetAndCompute(brokenChecksumSegment)
		if !bytes.Equal(modified, tcpSegment) {
			t.Errorf("SetAndCompute modified segment incorrectly")
		}
		if !calc.Verify(modified) {
			t.Errorf("expected SetAndCompute to set a valid checksum")
		}
	})
}
