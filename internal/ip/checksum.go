package ip

import (
	"net"
)

// Checksum computes the one's complement checksum of a byte slice.
func Checksum(data []byte) uint16 {
	var sum uint32
	length := len(data)
	for i := 0; i < length-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if length%2 != 0 {
		sum += uint32(data[length-1]) << 8
	}

	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// ChecksumCombine combines two checksums into a single one's complement checksum.
func ChecksumCombine(a, b uint16) uint16 {
	sum := uint32(^a) + uint32(^b)
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// VerifyChecksum returns true if the checksum of the data (which includes its checksum field) is correct.
func VerifyChecksum(data []byte) bool {
	return Checksum(data) == 0
}

// TCPChecksum calculates the TCP checksum including the IPv4 pseudo-header.
func TCPChecksum(src, dst net.IP, tcpSegment []byte) uint16 {
	src4 := src.To4()
	dst4 := dst.To4()

	var sum uint32

	// Pseudo-header
	if src4 != nil && dst4 != nil {
		// Source Address (4 bytes)
		sum += uint32(src4[0])<<8 | uint32(src4[1])
		sum += uint32(src4[2])<<8 | uint32(src4[3])
		// Destination Address (4 bytes)
		sum += uint32(dst4[0])<<8 | uint32(dst4[1])
		sum += uint32(dst4[2])<<8 | uint32(dst4[3])
	}

	// Reserved (1 byte) + Protocol (1 byte)
	sum += uint32(ProtoTCP)
	// TCP Length (2 bytes)
	sum += uint32(len(tcpSegment))

	// TCP Segment
	length := len(tcpSegment)
	for i := 0; i < length-1; i += 2 {
		sum += uint32(tcpSegment[i])<<8 | uint32(tcpSegment[i+1])
	}
	if length%2 != 0 {
		sum += uint32(tcpSegment[length-1]) << 8
	}

	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// ICMPChecksum calculates the checksum of an ICMP message.
func ICMPChecksum(icmpMsg []byte) uint16 {
	return Checksum(icmpMsg)
}
