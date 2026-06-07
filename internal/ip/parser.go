package ip

import (
	"fmt"
	"net"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type ParsedPacket struct {
	IPHeader  *Header
	Protocol  uint8
	SrcIP     net.IP
	DstIP     net.IP
	Payload   []byte
	TCPLayer  *layers.TCP
	UDPLayer  *layers.UDP
	ICMPLayer *layers.ICMPv4
}

// Parse uses manual parser for header, and gopacket for upper layers if needed.
func Parse(raw []byte) (*ParsedPacket, error) {
	ipHeader, err := ParseHeader(raw)
	if err != nil {
		return nil, err
	}

	p := &ParsedPacket{
		IPHeader: ipHeader,
		Protocol: ipHeader.Protocol,
		SrcIP:    ipHeader.Src,
		DstIP:    ipHeader.Dst,
		Payload:  ipHeader.Payload(raw),
	}

	if p.Payload != nil {
		switch p.Protocol {
		case ProtoTCP:
			tcp := &layers.TCP{}
			if err := tcp.DecodeFromBytes(p.Payload, gopacket.NilDecodeFeedback); err == nil {
				p.TCPLayer = tcp
			}
		case ProtoUDP:
			udp := &layers.UDP{}
			if err := udp.DecodeFromBytes(p.Payload, gopacket.NilDecodeFeedback); err == nil {
				p.UDPLayer = udp
			}
		case ProtoICMP:
			icmp := &layers.ICMPv4{}
			if err := icmp.DecodeFromBytes(p.Payload, gopacket.NilDecodeFeedback); err == nil {
				p.ICMPLayer = icmp
			}
		}
	}

	return p, nil
}

// ParseDebug always uses gopacket to parse everything.
func ParseDebug(raw []byte) (*ParsedPacket, error) {
	packet := gopacket.NewPacket(raw, layers.LayerTypeIPv4, gopacket.Default)
	if err := packet.ErrorLayer(); err != nil {
		return nil, err.Error()
	}

	ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ipv4Layer == nil {
		return nil, fmt.Errorf("not an IPv4 packet")
	}
	ipv4 := ipv4Layer.(*layers.IPv4)

	p := &ParsedPacket{
		Protocol: uint8(ipv4.Protocol),
		SrcIP:    ipv4.SrcIP,
		DstIP:    ipv4.DstIP,
		Payload:  ipv4.Payload,
	}

	// Also parse manual header for IPHeader field compatibility
	if h, err := ParseHeader(raw); err == nil {
		p.IPHeader = h
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		p.TCPLayer = tcpLayer.(*layers.TCP)
	}
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		p.UDPLayer = udpLayer.(*layers.UDP)
	}
	if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		p.ICMPLayer = icmpLayer.(*layers.ICMPv4)
	}

	return p, nil
}

// Summary returns a readable summary.
func (p *ParsedPacket) Summary() string {
	var proto string
	var src, dst string
	var info string

	src = p.SrcIP.String()
	dst = p.DstIP.String()

	switch {
	case p.TCPLayer != nil:
		proto = "TCP"
		src = fmt.Sprintf("%s:%d", src, p.TCPLayer.SrcPort)
		dst = fmt.Sprintf("%s:%d", dst, p.TCPLayer.DstPort)

		var flags []string
		if p.TCPLayer.SYN {
			flags = append(flags, "SYN")
		}
		if p.TCPLayer.ACK {
			flags = append(flags, "ACK")
		}
		if p.TCPLayer.FIN {
			flags = append(flags, "FIN")
		}
		if p.TCPLayer.RST {
			flags = append(flags, "RST")
		}
		if p.TCPLayer.PSH {
			flags = append(flags, "PSH")
		}
		if p.TCPLayer.URG {
			flags = append(flags, "URG")
		}

		info = fmt.Sprintf("[%s] seq=%d len=%d", strings.Join(flags, ","), p.TCPLayer.Seq, len(p.TCPLayer.Payload))

	case p.UDPLayer != nil:
		proto = "UDP"
		src = fmt.Sprintf("%s:%d", src, p.UDPLayer.SrcPort)
		dst = fmt.Sprintf("%s:%d", dst, p.UDPLayer.DstPort)
		info = fmt.Sprintf("len=%d", p.UDPLayer.Length)

	case p.ICMPLayer != nil:
		proto = "ICMP"
		info = fmt.Sprintf("type=%d code=%d", p.ICMPLayer.TypeCode.Type(), p.ICMPLayer.TypeCode.Code())

	default:
		proto = fmt.Sprintf("PROTO-%d", p.Protocol)
		info = fmt.Sprintf("len=%d", len(p.Payload))
	}

	if info != "" {
		return fmt.Sprintf("%s %s -> %s %s", proto, src, dst, info)
	}
	return fmt.Sprintf("%s %s -> %s", proto, src, dst)
}
