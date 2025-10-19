package main

import (
	"fmt"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// PacketParser 数据包解析器
type PacketParser struct {
	reassembler *StreamReassembler // TCP流重组器
}

// NewPacketParser 创建解析器
func NewPacketParser() *PacketParser {
	return &PacketParser{
		reassembler: NewStreamReassembler(),
	}
}

// Stop 停止解析器（清理资源）
func (p *PacketParser) Stop() {
	if p.reassembler != nil {
		p.reassembler.Stop()
	}
}

// Parse 解析数据包，返回结构化的PacketInfo
// 如果数据包需要缓冲（TCP分片），返回nil，等待完整数据
func (p *PacketParser) Parse(packet gopacket.Packet) *PacketInfo {
	// 先使用流重组器处理TCP分片
	reassembledPayload, ready, flowKey := p.reassembler.ProcessPacket(packet)

	// 如果数据还不完整，返回nil（等待更多分片）
	if !ready {
		return nil
	}

	info := &PacketInfo{
		Timestamp: packet.Metadata().Timestamp,
		Length:    packet.Metadata().Length,
		RawData:   packet.Data(),
	}

	// 1. 解析网络层（IP）
	p.parseNetworkLayer(packet, info)

	// 2. 解析传输层（TCP/UDP）
	p.parseTransportLayer(packet, info)

	// 3. 如果有重组的payload，使用它来解析应用层
	if reassembledPayload != nil && len(reassembledPayload) > 0 {
		info.Payload = reassembledPayload
		// 解析应用层（使用重组后的完整payload）
		p.parseApplicationLayerWithPayload(info)
	} else {
		// 否则使用原始应用层解析
		p.parseApplicationLayer(packet, info)
	}

	// 4. 判断流量方向
	p.determineDirection(info)

	// 5. 存储flowKey信息（用于调试）
	_ = flowKey

	return info
}

// parseNetworkLayer 解析网络层
func (p *PacketParser) parseNetworkLayer(packet gopacket.Packet, info *PacketInfo) {
	if ipLayer := packet.NetworkLayer(); ipLayer != nil {
		src, dst := ipLayer.NetworkFlow().Endpoints()
		info.SrcIP = src.String()
		info.DstIP = dst.String()
	}
}

// parseTransportLayer 解析传输层
func (p *PacketParser) parseTransportLayer(packet gopacket.Packet, info *PacketInfo) {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		info.Protocol = "TCP"
		info.SrcPort = tcp.SrcPort.String()
		info.DstPort = tcp.DstPort.String()
		info.SequenceNum = tcp.Seq
		info.AckNum = tcp.Ack

		// 解析TCP标志位
		flags := []string{}
		if tcp.SYN {
			flags = append(flags, "SYN")
		}
		if tcp.ACK {
			flags = append(flags, "ACK")
		}
		if tcp.FIN {
			flags = append(flags, "FIN")
		}
		if tcp.RST {
			flags = append(flags, "RST")
		}
		if tcp.PSH {
			flags = append(flags, "PSH")
		}
		if tcp.URG {
			flags = append(flags, "URG")
		}
		info.TCPFlags = strings.Join(flags, ",")

		// 获取payload
		info.Payload = tcp.Payload
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		info.Protocol = "UDP"
		info.SrcPort = udp.SrcPort.String()
		info.DstPort = udp.DstPort.String()
		info.Payload = udp.Payload
	}
}

// parseApplicationLayer 解析应用层
func (p *PacketParser) parseApplicationLayer(packet gopacket.Packet, info *PacketInfo) {
	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		info.AppProtocol = appLayer.LayerType().String()
	}

	// 如果有payload，尝试检测协议
	if len(info.Payload) > 0 {
		// 尝试解析TLS
		p.parseTLS(info)

		// 尝试解析DNS（UDP端口53）
		if info.Protocol == "UDP" && (info.SrcPort == "53(domain)" || info.DstPort == "53(domain)") {
			p.parseDNS(packet, info)
		}
	}
}

// parseApplicationLayerWithPayload 使用重组后的payload解析应用层
func (p *PacketParser) parseApplicationLayerWithPayload(info *PacketInfo) {
	// 尝试检测TLS协议
	if len(info.Payload) > 0 {
		p.parseTLS(info)
	}
}

// parseTLS 解析TLS协议
func (p *PacketParser) parseTLS(info *PacketInfo) {
	payload := info.Payload

	// 检查是否为TLS握手包
	if !p.isTLSHandshake(payload) {
		return
	}

	info.IsTLS = true

	// 解析TLS版本
	if len(payload) >= 3 {
		version := uint16(payload[1])<<8 | uint16(payload[2])
		info.TLSVersion = p.getTLSVersionString(version)
	}

	// 尝试提取SNI
	sni := p.extractSNI(payload)
	if sni != "" {
		info.SNI = sni
	}
}

// isTLSHandshake 检查是否为TLS握手包
func (p *PacketParser) isTLSHandshake(payload []byte) bool {
	if len(payload) < 6 {
		return false
	}

	// 检查Content Type (0x16 = Handshake)
	if payload[0] != 0x16 {
		return false
	}

	// 检查TLS版本
	version := uint16(payload[1])<<8 | uint16(payload[2])
	// 允许 TLS 1.0 - 1.3
	if version < 0x0301 || version > 0x0304 {
		return false
	}

	return true
}

// getTLSVersionString 获取TLS版本字符串
func (p *PacketParser) getTLSVersionString(version uint16) string {
	switch version {
	case 0x0301:
		return "TLS 1.0"
	case 0x0302:
		return "TLS 1.1"
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

// extractSNI 从TLS ClientHello包中提取SNI信息
func (p *PacketParser) extractSNI(payload []byte) string {
	// TLS Record Layer:
	// - Content Type (1 byte): 0x16 (Handshake)
	// - Version (2 bytes)
	// - Length (2 bytes)
	// - Handshake Protocol follows...

	if len(payload) < 6 {
		return ""
	}

	// 检查是否为TLS Handshake (Content Type = 0x16)
	if payload[0] != 0x16 {
		return ""
	}

	// TLS Record长度
	recordLen := int(payload[3])<<8 | int(payload[4])
	if len(payload) < 5+recordLen {
		return ""
	}

	// Handshake Protocol开始于offset 5
	pos := 5

	// Handshake Type (1 byte): 0x01 = ClientHello
	if pos >= len(payload) || payload[pos] != 0x01 {
		return ""
	}
	pos++

	// Handshake Length (3 bytes)
	if pos+3 > len(payload) {
		return ""
	}
	pos += 3

	// ClientHello Version (2 bytes)
	if pos+2 > len(payload) {
		return ""
	}
	pos += 2

	// Random (32 bytes)
	if pos+32 > len(payload) {
		return ""
	}
	pos += 32

	// Session ID Length (1 byte)
	if pos >= len(payload) {
		return ""
	}
	sessionIDLen := int(payload[pos])
	pos++

	// Session ID
	if pos+sessionIDLen > len(payload) {
		return ""
	}
	pos += sessionIDLen

	// Cipher Suites Length (2 bytes)
	if pos+2 > len(payload) {
		return ""
	}
	cipherSuitesLen := int(payload[pos])<<8 | int(payload[pos+1])
	pos += 2

	// Cipher Suites
	if pos+cipherSuitesLen > len(payload) {
		return ""
	}
	pos += cipherSuitesLen

	// Compression Methods Length (1 byte)
	if pos >= len(payload) {
		return ""
	}
	compressionMethodsLen := int(payload[pos])
	pos++

	// Compression Methods
	if pos+compressionMethodsLen > len(payload) {
		return ""
	}
	pos += compressionMethodsLen

	// Extensions Length (2 bytes)
	if pos+2 > len(payload) {
		return "" // 没有扩展
	}
	extensionsLen := int(payload[pos])<<8 | int(payload[pos+1])
	pos += 2

	if pos+extensionsLen > len(payload) {
		return ""
	}

	// 遍历扩展
	extensionsEnd := pos + extensionsLen
	for pos+4 <= extensionsEnd {
		// Extension Type (2 bytes)
		extType := uint16(payload[pos])<<8 | uint16(payload[pos+1])
		pos += 2

		// Extension Length (2 bytes)
		extLen := int(payload[pos])<<8 | int(payload[pos+1])
		pos += 2

		if pos+extLen > len(payload) {
			return ""
		}

		// 检查是否为SNI扩展 (type = 0x0000)
		if extType == 0x0000 {
			return p.parseSNIExtension(payload[pos : pos+extLen])
		}

		pos += extLen
	}

	return ""
}

// parseSNIExtension 解析SNI扩展内容
func (p *PacketParser) parseSNIExtension(data []byte) string {
	// Server Name List Length (2 bytes)
	if len(data) < 2 {
		return ""
	}
	listLen := int(data[0])<<8 | int(data[1])
	if len(data) < 2+listLen {
		return ""
	}

	pos := 2

	// Server Name
	for pos+3 <= len(data) {
		// Name Type (1 byte): 0x00 = hostname
		nameType := data[pos]
		pos++

		// Name Length (2 bytes)
		nameLen := int(data[pos])<<8 | int(data[pos+1])
		pos += 2

		if pos+nameLen > len(data) {
			return ""
		}

		// 如果是hostname类型，返回域名
		if nameType == 0x00 {
			return string(data[pos : pos+nameLen])
		}

		pos += nameLen
	}

	return ""
}

// determineDirection 判断流量方向
func (p *PacketParser) determineDirection(info *PacketInfo) {
	srcIsLocal := isLocalIP(info.SrcIP)
	dstIsLocal := isLocalIP(info.DstIP)

	if srcIsLocal && !dstIsLocal {
		// 源是本地，目标是远程 -> 发送
		info.Direction = "send"
		info.RemoteIP = info.DstIP
		info.LocalPort = info.SrcPort
		info.RemotePort = info.DstPort
	} else if !srcIsLocal && dstIsLocal {
		// 源是远程，目标是本地 -> 接收
		info.Direction = "recv"
		info.RemoteIP = info.SrcIP
		info.LocalPort = info.DstPort
		info.RemotePort = info.SrcPort
	} else if !srcIsLocal && !dstIsLocal {
		// 两者都是远程IP，选择目标作为远程IP（可能是转发流量）
		info.Direction = "send"
		info.RemoteIP = info.DstIP
		info.LocalPort = info.SrcPort
		info.RemotePort = info.DstPort
	} else {
		// 两者都是本地IP（内网通信）
		info.Direction = "local"
		info.RemoteIP = info.DstIP
		info.LocalPort = info.SrcPort
		info.RemotePort = info.DstPort
	}
}

// isLocalIP 判断是否为本地IP地址
func isLocalIP(ip string) bool {
	// 检查是否为私有IP地址范围
	// 10.0.0.0/8
	// 172.16.0.0/12
	// 192.168.0.0/16
	// 127.0.0.0/8 (loopback)
	if strings.HasPrefix(ip, "10.") ||
		strings.HasPrefix(ip, "192.168.") ||
		strings.HasPrefix(ip, "127.") ||
		strings.HasPrefix(ip, "169.254.") { // Link-local
		return true
	}

	// 检查 172.16.0.0/12 范围
	if strings.HasPrefix(ip, "172.") {
		parts := strings.Split(ip, ".")
		if len(parts) >= 2 {
			var secondOctet int
			fmt.Sscanf(parts[1], "%d", &secondOctet)
			if secondOctet >= 16 && secondOctet <= 31 {
				return true
			}
		}
	}

	return false
}

// parseDNS 解析DNS包
func (p *PacketParser) parseDNS(packet gopacket.Packet, info *PacketInfo) {
	// 使用gopacket的DNS层
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return
	}

	dns, ok := dnsLayer.(*layers.DNS)
	if !ok {
		return
	}

	info.IsDNS = true

	// 检查是否为DNS响应包 (QR=1表示响应)
	if !dns.QR {
		return // 不是响应包，跳过
	}

	// 提取查询域名
	if len(dns.Questions) > 0 {
		info.DNSQueryName = string(dns.Questions[0].Name)
	}

	// 提取响应中的IP地址（A记录和AAAA记录）
	info.DNSResponseIPs = make([]string, 0)
	for _, answer := range dns.Answers {
		switch answer.Type {
		case layers.DNSTypeA:
			// IPv4地址
			if answer.IP != nil {
				info.DNSResponseIPs = append(info.DNSResponseIPs, answer.IP.String())
			}
		case layers.DNSTypeAAAA:
			// IPv6地址
			if answer.IP != nil {
				info.DNSResponseIPs = append(info.DNSResponseIPs, answer.IP.String())
			}
		}
	}
}
