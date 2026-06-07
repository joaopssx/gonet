package icmp

import (
	"net"

	"github.com/joaopssx/gonet/internal/ip"
	"github.com/joaopssx/gonet/internal/tun"
	"go.uber.org/zap"
)

type ICMPHandler struct {
	io  tun.PacketIO
	log *zap.Logger
}

func NewICMPHandler(io tun.PacketIO, log *zap.Logger) *ICMPHandler {
	if log == nil {
		log = zap.NewNop()
	}
	return &ICMPHandler{
		io:  io,
		log: log,
	}
}

func (h *ICMPHandler) Protocol() uint8 {
	return ip.ProtoICMP
}

func (h *ICMPHandler) HandleIPPayload(srcIP, dstIP net.IP, payload []byte) error {
	msg, err := ParseEcho(payload)
	if err != nil {
		if err == ErrNotEcho {
			// Ignore non-echo messages for now
			h.log.Debug("ignored non-echo ICMP message")
			return nil
		}
		return err
	}

	if msg.Type == TypeEchoRequest {
		h.log.Info("received ICMP Echo Request",
			zap.String("src", srcIP.String()),
			zap.String("dst", dstIP.String()),
			zap.Uint16("id", msg.ID),
			zap.Uint16("seq", msg.Seq))

		reply := NewEchoReply(msg)
		replyBytes, err := reply.Marshal()
		if err != nil {
			return err
		}

		builder := ip.NewPacketBuilder(dstIP, srcIP, ip.ProtoICMP)
		packetBytes, err := builder.Build(replyBytes)
		if err != nil {
			return err
		}

		_, err = h.io.Write(packetBytes)
		if err != nil {
			h.log.Error("failed to send ICMP Echo Reply", zap.Error(err))
			return err
		}

		h.log.Info("sent ICMP Echo Reply",
			zap.String("src", dstIP.String()),
			zap.String("dst", srcIP.String()),
			zap.Uint16("id", reply.ID),
			zap.Uint16("seq", reply.Seq))
	}

	return nil
}
