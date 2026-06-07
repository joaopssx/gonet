package icmp

import (
	"encoding/binary"
	"errors"

	"github.com/joaopssx/gonet/internal/ip"
)

type MessageType uint8

const (
	TypeEchoReply   MessageType = 0
	TypeEchoRequest MessageType = 8
	TypeUnreachable MessageType = 3
)

var (
	ErrTooShort = errors.New("ICMP message too short")
	ErrNotEcho  = errors.New("not an ICMP echo message")
)

type EchoMessage struct {
	Type     MessageType
	Code     uint8
	Checksum uint16
	ID       uint16
	Seq      uint16
	Data     []byte
}

func ParseEcho(raw []byte) (*EchoMessage, error) {
	if len(raw) < 8 {
		return nil, ErrTooShort
	}

	msgType := MessageType(raw[0])
	if msgType != TypeEchoRequest && msgType != TypeEchoReply {
		return nil, ErrNotEcho
	}

	m := &EchoMessage{
		Type:     msgType,
		Code:     raw[1],
		Checksum: binary.BigEndian.Uint16(raw[2:4]),
		ID:       binary.BigEndian.Uint16(raw[4:6]),
		Seq:      binary.BigEndian.Uint16(raw[6:8]),
	}

	if len(raw) > 8 {
		m.Data = make([]byte, len(raw)-8)
		copy(m.Data, raw[8:])
	}

	return m, nil
}

func (m *EchoMessage) Marshal() ([]byte, error) {
	buf := make([]byte, 8+len(m.Data))
	buf[0] = uint8(m.Type)
	buf[1] = m.Code
	buf[2] = 0 // Checksum initialized to 0
	buf[3] = 0
	binary.BigEndian.PutUint16(buf[4:6], m.ID)
	binary.BigEndian.PutUint16(buf[6:8], m.Seq)

	if len(m.Data) > 0 {
		copy(buf[8:], m.Data)
	}

	checksum := ip.ICMPChecksum(buf)
	binary.BigEndian.PutUint16(buf[2:4], checksum)

	return buf, nil
}

func NewEchoReply(req *EchoMessage) *EchoMessage {
	return &EchoMessage{
		Type: TypeEchoReply,
		Code: 0,
		ID:   req.ID,
		Seq:  req.Seq,
		Data: req.Data, // Copies payload back
	}
}
