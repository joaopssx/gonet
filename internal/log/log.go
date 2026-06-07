package log

import (
	"encoding/hex"
	"net"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Constants for common logging fields to ensure consistency across the networking stack.
const (
	FieldProto   = "proto"
	FieldSrcIP   = "src_ip"
	FieldDstIP   = "dst_ip"
	FieldSrcPort = "src_port"
	FieldDstPort = "dst_port"
	FieldState   = "state"
	FieldSeq     = "seq"
	FieldAck     = "ack"
)

// New creates a new zap.Logger configured with the specified level and format.
// If pretty is true, it uses a development-friendly console encoder; otherwise, a JSON production encoder.
func New(level string, pretty bool) (*zap.Logger, error) {
	var config zap.Config
	if pretty {
		config = zap.NewDevelopmentConfig()
		config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	} else {
		config = zap.NewProductionConfig()
	}

	parsedLevel, err := zapcore.ParseLevel(strings.ToLower(level))
	if err != nil {
		// Fallback to info level if string parsing fails
		parsedLevel = zapcore.InfoLevel
	}
	config.Level = zap.NewAtomicLevelAt(parsedLevel)

	return config.Build()
}

// WithPacket returns a logger enriched with IP packet context.
func WithPacket(log *zap.Logger, proto uint8, src, dst net.IP) *zap.Logger {
	return log.With(
		zap.Uint8(FieldProto, proto),
		zap.Stringer(FieldSrcIP, src),
		zap.Stringer(FieldDstIP, dst),
	)
}

// WithConn returns a logger enriched with TCP connection context.
func WithConn(log *zap.Logger, srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16) *zap.Logger {
	return log.With(
		zap.Stringer(FieldSrcIP, srcIP),
		zap.Uint16(FieldSrcPort, srcPort),
		zap.Stringer(FieldDstIP, dstIP),
		zap.Uint16(FieldDstPort, dstPort),
	)
}

// HexDump returns a hexadecimal string representation of the first maxBytes of data.
// If the data length exceeds maxBytes, the output is truncated and suffixed with "...".
// This is useful for debug-logging payloads without polluting the logs with huge strings.
func HexDump(data []byte, maxBytes int) string {
	if len(data) == 0 {
		return ""
	}
	if len(data) <= maxBytes {
		return hex.EncodeToString(data)
	}
	return hex.EncodeToString(data[:maxBytes]) + "..."
}
