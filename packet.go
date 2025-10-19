package main

import "time"

// PacketInfo 解析后的数据包信息
type PacketInfo struct {
	// 基础信息
	Timestamp time.Time
	Length    int

	// 网络层
	SrcIP string
	DstIP string

	// 传输层
	Protocol   string // TCP/UDP/ICMP等
	SrcPort    string
	DstPort    string
	TCPFlags   string // TCP标志位（SYN, ACK等）
	SequenceNum uint32
	AckNum     uint32

	// 应用层
	AppProtocol string // HTTP/TLS/DNS等
	Payload     []byte

	// TLS相关
	IsTLS       bool
	TLSVersion  string
	SNI         string // Server Name Indication
	CipherSuite string

	// DNS相关
	IsDNS          bool     // 是否为DNS包
	DNSQueryName   string   // DNS查询域名
	DNSResponseIPs []string // DNS回应中的IP地址列表

	// 流量方向和分类
	Direction  string // send/recv/local
	RemoteIP   string // 远程IP
	LocalPort  string // 本地端口
	RemotePort string // 远程端口

	// 进程信息
	ProcessName string
	ProcessPID  uint32

	// 原始包数据（用于保存pcap）
	RawData []byte
}

// FlowKey 流标识（用于会话重组）
type FlowKey struct {
	SrcIP   string
	DstIP   string
	SrcPort string
	DstPort string
	Proto   string
}

// String 返回流的字符串表示
func (fk FlowKey) String() string {
	return fk.SrcIP + ":" + fk.SrcPort + "->" + fk.DstIP + ":" + fk.DstPort + "/" + fk.Proto
}

// Reverse 返回反向流
func (fk FlowKey) Reverse() FlowKey {
	return FlowKey{
		SrcIP:   fk.DstIP,
		DstIP:   fk.SrcIP,
		SrcPort: fk.DstPort,
		DstPort: fk.SrcPort,
		Proto:   fk.Proto,
	}
}
