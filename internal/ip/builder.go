package ip

import (
	"errors"
	"net"
	"sync/atomic"
)

// IDGenerator generates sequential 16-bit IDs wrapping around at 65535.
type IDGenerator struct {
	val atomic.Uint32
}

// Next returns the next ID, safely wrapping around 16 bits.
func (g *IDGenerator) Next() uint16 {
	return uint16(g.val.Add(1))
}

var defaultIDGen = &IDGenerator{}

type PacketBuilder struct {
	src   net.IP
	dst   net.IP
	proto uint8
	ttl   uint8
	tos   uint8
	idGen *IDGenerator
}

type buildContext struct {
	ttl   uint8
	tos   uint8
	flags uint8
	id    uint16
}

type BuildOption func(*buildContext)

// WithTTL overrides the default TTL.
func WithTTL(n uint8) BuildOption {
	return func(c *buildContext) {
		c.ttl = n
	}
}

// WithTOS overrides the default Type of Service.
func WithTOS(n uint8) BuildOption {
	return func(c *buildContext) {
		c.tos = n
	}
}

// WithDF sets the Don't Fragment flag.
func WithDF() BuildOption {
	return func(c *buildContext) {
		c.flags |= FlagDF
	}
}

// WithID overrides the auto-generated ID.
func WithID(id uint16) BuildOption {
	return func(c *buildContext) {
		c.id = id
	}
}

var ErrPacketTooLarge = errors.New("packet too large")

// NewPacketBuilder creates a new builder for a specific source, destination, and protocol.
func NewPacketBuilder(src, dst net.IP, proto uint8) *PacketBuilder {
	return &PacketBuilder{
		src:   src,
		dst:   dst,
		proto: proto,
		ttl:   DefaultTTL,
		tos:   0,
		idGen: defaultIDGen, // shared generator for unique IDs globally
	}
}

// Build creates an IP packet with the provided payload and default options.
func (b *PacketBuilder) Build(payload []byte) ([]byte, error) {
	return b.BuildWithOptions(payload)
}

// BuildWithOptions creates an IP packet, allowing override of TTL, TOS, Flags, or ID.
func (b *PacketBuilder) BuildWithOptions(payload []byte, opts ...BuildOption) ([]byte, error) {
	ctx := buildContext{
		ttl:   b.ttl,
		tos:   b.tos,
		flags: 0,
		id:    b.idGen.Next(),
	}

	for _, opt := range opts {
		opt(&ctx)
	}

	totalLen := MinHeaderLen + len(payload)
	if totalLen > 0xFFFF {
		return nil, ErrPacketTooLarge
	}

	h := &Header{
		Version:    4,
		IHL:        MinHeaderLen / 4,
		TOS:        ctx.tos,
		TotalLen:   uint16(totalLen),
		ID:         ctx.id,
		Flags:      ctx.flags,
		FragOffset: 0,
		TTL:        ctx.ttl,
		Protocol:   b.proto,
		Checksum:   0, // initial checksum is 0
		Src:        b.src,
		Dst:        b.dst,
	}

	// Marshal without checksum
	headerBytes, err := h.Marshal()
	if err != nil {
		return nil, err
	}

	// Compute checksum
	h.Checksum = Checksum(headerBytes)

	// Re-marshal with correct checksum
	headerBytes, err = h.Marshal()
	if err != nil {
		return nil, err
	}

	packet := make([]byte, 0, totalLen)
	packet = append(packet, headerBytes...)
	packet = append(packet, payload...)

	return packet, nil
}
