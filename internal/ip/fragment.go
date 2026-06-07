package ip

import (
	"errors"
)

var (
	ErrDontFragment = errors.New("fragmentation required but DF flag is set")
	ErrMTUTooSmall  = errors.New("MTU is too small for IPv4 header")
)

// NeedsFragmentation returns true if the packet length exceeds the MTU.
func NeedsFragmentation(packetLen, mtu int) bool {
	return packetLen > mtu
}

// Fragment splits an IP packet into multiple fragments to fit within the given MTU.
func Fragment(packet []byte, mtu int) ([][]byte, error) {
	if !NeedsFragmentation(len(packet), mtu) {
		return [][]byte{packet}, nil
	}

	header, err := ParseHeader(packet)
	if err != nil {
		return nil, err
	}

	if (header.Flags & FlagDF) != 0 {
		return nil, ErrDontFragment
	}

	headerLen := header.HeaderLen()
	// MTU must at least accommodate the header plus an 8-byte payload block
	if mtu < headerLen+8 {
		return nil, ErrMTUTooSmall
	}

	// Payload available per fragment must be a multiple of 8
	maxPayloadPerFragment := (mtu - headerLen) &^ 7

	payload := header.Payload(packet)
	payloadLen := len(payload)

	var fragments [][]byte
	var offset int // tracking byte offset in the current payload

	for offset < payloadLen {
		remaining := payloadLen - offset
		fragmentPayloadLen := maxPayloadPerFragment

		isLast := false
		if remaining <= maxPayloadPerFragment {
			fragmentPayloadLen = remaining
			isLast = true
		}

		fragHeader := *header
		// Calculate the correct FragOffset (incorporating any existing offset)
		fragHeader.FragOffset = header.FragOffset + uint16(offset/8)
		fragHeader.TotalLen = uint16(headerLen + fragmentPayloadLen)

		if !isLast {
			fragHeader.Flags |= FlagMF
		} else {
			// For the last sub-fragment, retain the original MF flag
			// which could be 1 if this packet is already a fragment.
			fragHeader.Flags = header.Flags
		}

		// Recalculate checksum
		fragHeader.Checksum = 0
		headerBytes, err := fragHeader.Marshal()
		if err != nil {
			return nil, err
		}
		fragHeader.Checksum = Checksum(headerBytes)

		// Final marshal with correct checksum
		headerBytes, _ = fragHeader.Marshal()

		fragPacket := make([]byte, 0, headerLen+fragmentPayloadLen)
		fragPacket = append(fragPacket, headerBytes...)
		fragPacket = append(fragPacket, payload[offset:offset+fragmentPayloadLen]...)

		fragments = append(fragments, fragPacket)

		offset += fragmentPayloadLen
	}

	return fragments, nil
}
