package ip

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

const (
	FlagDF = 0x02
	FlagMF = 0x01

	ProtoICMP = 1
	ProtoTCP  = 6
	ProtoUDP  = 17

	MinHeaderLen = 20
	DefaultTTL   = 64
)

var (
	ErrTooShort = errors.New("packet too short")
	ErrInvalid  = errors.New("invalid IPv4 header")
)

type Header struct {
	Version    uint8
	IHL        uint8
	TOS        uint8
	TotalLen   uint16
	ID         uint16
	Flags      uint8
	FragOffset uint16
	TTL        uint8
	Protocol   uint8
	Checksum   uint16
	Src        net.IP
	Dst        net.IP
	Options    []byte
}

func ParseHeader(raw []byte) (*Header, error) {
	if len(raw) < MinHeaderLen {
		return nil, ErrTooShort
	}

	versionAndIHL := raw[0]
	version := versionAndIHL >> 4
	ihl := versionAndIHL & 0x0F

	if version != 4 {
		return nil, ErrInvalid
	}

	headerLen := int(ihl) * 4
	if len(raw) < headerLen {
		return nil, ErrTooShort
	}

	totalLen := binary.BigEndian.Uint16(raw[2:4])
	if int(totalLen) < headerLen {
		return nil, ErrInvalid
	}

	flagsAndOffset := binary.BigEndian.Uint16(raw[6:8])
	flags := uint8(flagsAndOffset >> 13)
	fragOffset := flagsAndOffset & 0x1FFF

	h := &Header{
		Version:    version,
		IHL:        ihl,
		TOS:        raw[1],
		TotalLen:   totalLen,
		ID:         binary.BigEndian.Uint16(raw[4:6]),
		Flags:      flags,
		FragOffset: fragOffset,
		TTL:        raw[8],
		Protocol:   raw[9],
		Checksum:   binary.BigEndian.Uint16(raw[10:12]),
		Src:        net.IP(raw[12:16]),
		Dst:        net.IP(raw[16:20]),
	}

	if headerLen > MinHeaderLen {
		h.Options = raw[20:headerLen]
	}

	return h, nil
}

func (h *Header) Marshal() ([]byte, error) {
	headerLen := h.HeaderLen()
	buf := make([]byte, headerLen)

	buf[0] = (h.Version << 4) | (h.IHL & 0x0F)
	buf[1] = h.TOS
	binary.BigEndian.PutUint16(buf[2:4], h.TotalLen)
	binary.BigEndian.PutUint16(buf[4:6], h.ID)

	flagsAndOffset := (uint16(h.Flags) << 13) | (h.FragOffset & 0x1FFF)
	binary.BigEndian.PutUint16(buf[6:8], flagsAndOffset)

	buf[8] = h.TTL
	buf[9] = h.Protocol
	binary.BigEndian.PutUint16(buf[10:12], h.Checksum)

	if src := h.Src.To4(); src != nil {
		copy(buf[12:16], src)
	}
	if dst := h.Dst.To4(); dst != nil {
		copy(buf[16:20], dst)
	}

	if len(h.Options) > 0 {
		copy(buf[20:], h.Options)
	}

	return buf, nil
}

func (h *Header) HeaderLen() int {
	return int(h.IHL) * 4
}

func (h *Header) Payload(raw []byte) []byte {
	headerLen := h.HeaderLen()
	if len(raw) <= headerLen {
		return nil
	}
	return raw[headerLen:]
}

func (h *Header) String() string {
	return fmt.Sprintf("IPv4{Src: %s, Dst: %s, Proto: %d, TTL: %d, Len: %d}", h.Src, h.Dst, h.Protocol, h.TTL, h.TotalLen)
}
