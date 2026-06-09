package tcp

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Constants for TCP flags
const (
	FlagFIN uint8 = 0x01
	FlagSYN uint8 = 0x02
	FlagRST uint8 = 0x04
	FlagPSH uint8 = 0x08
	FlagACK uint8 = 0x10
	FlagURG uint8 = 0x20
	FlagECE uint8 = 0x40
	FlagCWR uint8 = 0x80
)

// Constants for TCP options
const (
	OptEndOfList   uint8 = 0
	OptNOP         uint8 = 1
	OptMSS         uint8 = 2
	OptWindowScale uint8 = 3
	OptSACKPermit  uint8 = 4
	OptSACK        uint8 = 5
	OptTimestamps  uint8 = 8
)

// MinHeaderLen is the minimum length of a TCP header in bytes.
const MinHeaderLen = 20

// TCPOption represents a single TCP option
type TCPOption struct {
	Kind   uint8
	Length uint8
	Data   []byte
}

// Header represents a parsed TCP header
type Header struct {
	SrcPort    uint16
	DstPort    uint16
	SeqNum     uint32
	AckNum     uint32
	DataOffset uint8
	Flags      uint8
	Window     uint16
	Checksum   uint16
	Urgent     uint16
	Options    []TCPOption
}

var (
	// ErrHeaderTooShort is returned when parsing a slice smaller than MinHeaderLen
	ErrHeaderTooShort = errors.New("tcp header too short")
	// ErrInvalidDataOffset is returned when the data offset is less than 5
	ErrInvalidDataOffset = errors.New("invalid tcp data offset")
	// ErrMalformedOptions is returned when TCP options cannot be parsed
	ErrMalformedOptions = errors.New("malformed tcp options")
)

// ParseHeader parses a raw byte slice into a TCP Header
func ParseHeader(raw []byte) (*Header, error) {
	if len(raw) < MinHeaderLen {
		return nil, ErrHeaderTooShort
	}

	h := &Header{
		SrcPort:  binary.BigEndian.Uint16(raw[0:2]),
		DstPort:  binary.BigEndian.Uint16(raw[2:4]),
		SeqNum:   binary.BigEndian.Uint32(raw[4:8]),
		AckNum:   binary.BigEndian.Uint32(raw[8:12]),
		Window:   binary.BigEndian.Uint16(raw[14:16]),
		Checksum: binary.BigEndian.Uint16(raw[16:18]),
		Urgent:   binary.BigEndian.Uint16(raw[18:20]),
	}

	// byte 12: Data Offset (4 bits), Reserved (4 bits)
	h.DataOffset = raw[12] >> 4
	if h.DataOffset < 5 {
		return nil, ErrInvalidDataOffset
	}

	headerLenBytes := int(h.DataOffset) * 4
	if len(raw) < headerLenBytes {
		return nil, errors.New("tcp header length exceeds packet size")
	}

	// byte 13: CWR, ECE, URG, ACK, PSH, RST, SYN, FIN
	h.Flags = raw[13]

	// Parse options if present
	if headerLenBytes > MinHeaderLen {
		optionsData := raw[MinHeaderLen:headerLenBytes]
		opts, err := ParseOptions(optionsData)
		if err != nil {
			return nil, err
		}
		h.Options = opts
	}

	return h, nil
}

// ParseOptions parses the TCP options field
func ParseOptions(data []byte) ([]TCPOption, error) {
	var options []TCPOption
	i := 0
	for i < len(data) {
		kind := data[i]
		if kind == OptEndOfList {
			// End of options list
			break
		}
		if kind == OptNOP {
			options = append(options, TCPOption{Kind: kind})
			i++
			continue
		}

		if i+1 >= len(data) {
			return nil, fmt.Errorf("%w: missing length for option %d", ErrMalformedOptions, kind)
		}

		length := data[i+1]
		if length < 2 {
			return nil, fmt.Errorf("%w: length %d too short for option %d", ErrMalformedOptions, length, kind)
		}

		if i+int(length) > len(data) {
			return nil, fmt.Errorf("%w: length %d exceeds available data for option %d", ErrMalformedOptions, length, kind)
		}

		optData := data[i+2 : i+int(length)]
		options = append(options, TCPOption{
			Kind:   kind,
			Length: length,
			Data:   optData,
		})

		i += int(length)
	}

	return options, nil
}

// Marshal serializes the TCP Header into a byte slice
func (h *Header) Marshal() ([]byte, error) {
	var optsBytes []byte
	for _, opt := range h.Options {
		if opt.Kind == OptEndOfList {
			optsBytes = append(optsBytes, OptEndOfList)
			break
		}
		if opt.Kind == OptNOP {
			optsBytes = append(optsBytes, OptNOP)
			continue
		}
		optsBytes = append(optsBytes, opt.Kind, opt.Length)
		optsBytes = append(optsBytes, opt.Data...)
	}

	// Pad options with OptEndOfList to make the total header length a multiple of 4 bytes
	for (MinHeaderLen+len(optsBytes))%4 != 0 {
		optsBytes = append(optsBytes, OptEndOfList)
	}

	dataOffset := uint8(MinHeaderLen+len(optsBytes)) / 4
	h.DataOffset = dataOffset

	buf := make([]byte, MinHeaderLen+len(optsBytes))
	binary.BigEndian.PutUint16(buf[0:2], h.SrcPort)
	binary.BigEndian.PutUint16(buf[2:4], h.DstPort)
	binary.BigEndian.PutUint32(buf[4:8], h.SeqNum)
	binary.BigEndian.PutUint32(buf[8:12], h.AckNum)

	buf[12] = h.DataOffset << 4 // ignoring 4 reserved bits
	buf[13] = h.Flags
	binary.BigEndian.PutUint16(buf[14:16], h.Window)
	binary.BigEndian.PutUint16(buf[16:18], h.Checksum)
	binary.BigEndian.PutUint16(buf[18:20], h.Urgent)

	copy(buf[MinHeaderLen:], optsBytes)

	return buf, nil
}

// HasFlag checks if a specific TCP flag is set
func (h *Header) HasFlag(flag uint8) bool {
	return h.Flags&flag != 0
}

// SetFlag sets a specific TCP flag
func (h *Header) SetFlag(flag uint8) {
	h.Flags |= flag
}

// HeaderLen returns the header length in bytes (DataOffset * 4)
// This is used instead of DataOffset() to avoid a naming conflict with the DataOffset struct field.
func (h *Header) HeaderLen() int {
	return int(h.DataOffset) * 4
}

// String returns a human-readable representation of the TCP header
func (h *Header) String() string {
	flagsStr := ""
	if h.HasFlag(FlagCWR) {
		flagsStr += "CWR "
	}
	if h.HasFlag(FlagECE) {
		flagsStr += "ECE "
	}
	if h.HasFlag(FlagURG) {
		flagsStr += "URG "
	}
	if h.HasFlag(FlagACK) {
		flagsStr += "ACK "
	}
	if h.HasFlag(FlagPSH) {
		flagsStr += "PSH "
	}
	if h.HasFlag(FlagRST) {
		flagsStr += "RST "
	}
	if h.HasFlag(FlagSYN) {
		flagsStr += "SYN "
	}
	if h.HasFlag(FlagFIN) {
		flagsStr += "FIN "
	}

	if len(flagsStr) > 0 {
		flagsStr = flagsStr[:len(flagsStr)-1] // remove trailing space
	}

	return fmt.Sprintf("TCP :%d -> :%d [%s] seq=%d ack=%d win=%d",
		h.SrcPort, h.DstPort, flagsStr, h.SeqNum, h.AckNum, h.Window)
}
