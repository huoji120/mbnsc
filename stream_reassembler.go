package main

import (
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	// 最大缓冲区大小 (65535字节)
	MaxBufferSize = 65535

	// 流超时时间 (3秒)
	StreamTimeout = 3 * time.Second

	// 清理过期流的间隔
	CleanupInterval = 1 * time.Second
)

// StreamBuffer TCP流缓冲区
type StreamBuffer struct {
	Buffer       []byte    // 缓冲的数据
	LastActivity time.Time // 最后活动时间
	NextSeq      uint32    // 期望的下一个序列号
	Initialized  bool      // 是否已初始化序列号
}

// StreamReassembler TCP流重组器
type StreamReassembler struct {
	streams map[FlowKey]*StreamBuffer
	mutex   sync.RWMutex
	stopCh  chan struct{}
}

// NewStreamReassembler 创建流重组器
func NewStreamReassembler() *StreamReassembler {
	sr := &StreamReassembler{
		streams: make(map[FlowKey]*StreamBuffer),
		stopCh:  make(chan struct{}),
	}

	// 启动定期清理goroutine
	go sr.cleanupLoop()

	return sr
}

// Stop 停止流重组器
func (sr *StreamReassembler) Stop() {
	close(sr.stopCh)
}

// cleanupLoop 定期清理过期的流
func (sr *StreamReassembler) cleanupLoop() {
	ticker := time.NewTicker(CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sr.cleanupExpiredStreams()
		case <-sr.stopCh:
			return
		}
	}
}

// cleanupExpiredStreams 清理过期的流
func (sr *StreamReassembler) cleanupExpiredStreams() {
	sr.mutex.Lock()
	defer sr.mutex.Unlock()

	now := time.Now()
	for key, stream := range sr.streams {
		if now.Sub(stream.LastActivity) > StreamTimeout {
			delete(sr.streams, key)
		}
	}
}

// ProcessPacket 处理数据包，返回是否有完整数据可供解析
// 返回值: (完整的payload数据, 是否准备好解析, FlowKey)
func (sr *StreamReassembler) ProcessPacket(packet gopacket.Packet) ([]byte, bool, FlowKey) {
	// 只处理TCP包
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		// 非TCP包，直接返回原始payload
		if appLayer := packet.ApplicationLayer(); appLayer != nil {
			return appLayer.Payload(), true, FlowKey{}
		}
		return nil, false, FlowKey{}
	}

	tcp, _ := tcpLayer.(*layers.TCP)

	// 获取网络层信息构建FlowKey
	var srcIP, dstIP string
	if ipLayer := packet.NetworkLayer(); ipLayer != nil {
		src, dst := ipLayer.NetworkFlow().Endpoints()
		srcIP = src.String()
		dstIP = dst.String()
	}

	flowKey := FlowKey{
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: tcp.SrcPort.String(),
		DstPort: tcp.DstPort.String(),
		Proto:   "TCP",
	}

	// 如果没有payload，直接返回
	if len(tcp.Payload) == 0 {
		return nil, false, flowKey
	}

	// 获取或创建流缓冲区
	sr.mutex.Lock()
	stream, exists := sr.streams[flowKey]
	if !exists {
		stream = &StreamBuffer{
			Buffer:       make([]byte, 0, MaxBufferSize),
			LastActivity: time.Now(),
			Initialized:  false,
		}
		sr.streams[flowKey] = stream
	}
	sr.mutex.Unlock()

	// 更新最后活动时间
	stream.LastActivity = time.Now()

	// 初始化序列号（第一个包）
	if !stream.Initialized {
		stream.NextSeq = tcp.Seq + uint32(len(tcp.Payload))
		stream.Initialized = true
		stream.Buffer = append(stream.Buffer, tcp.Payload...)
	} else {
		// 检查序列号是否连续
		if tcp.Seq == stream.NextSeq {
			// 序列号连续，追加数据
			if len(stream.Buffer)+len(tcp.Payload) <= MaxBufferSize {
				stream.Buffer = append(stream.Buffer, tcp.Payload...)
				stream.NextSeq = tcp.Seq + uint32(len(tcp.Payload))
			} else {
				// 缓冲区溢出，重置流
				stream.Buffer = make([]byte, 0, MaxBufferSize)
				stream.Buffer = append(stream.Buffer, tcp.Payload...)
				stream.NextSeq = tcp.Seq + uint32(len(tcp.Payload))
			}
		} else if tcp.Seq > stream.NextSeq {
			// 数据包乱序或丢失，可以选择等待或重置
			// 这里选择重置流（简单策略）
			stream.Buffer = make([]byte, 0, MaxBufferSize)
			stream.Buffer = append(stream.Buffer, tcp.Payload...)
			stream.NextSeq = tcp.Seq + uint32(len(tcp.Payload))
		}
		// 如果 tcp.Seq < stream.NextSeq，说明是重传，忽略
	}

	// Peek: 检查缓冲区是否有完整的TLS记录
	ready, completeData := sr.peekTLSRecord(stream.Buffer)

	if ready {
		// 有完整数据，清空缓冲区并返回
		sr.mutex.Lock()
		delete(sr.streams, flowKey)
		sr.mutex.Unlock()
		return completeData, true, flowKey
	}

	// 数据不完整，继续缓冲
	return nil, false, flowKey
}

// peekTLSRecord 检查缓冲区是否包含完整的TLS记录
// 返回: (是否完整, 完整的数据)
func (sr *StreamReassembler) peekTLSRecord(buffer []byte) (bool, []byte) {
	// TLS记录最小长度: 5字节 (Content Type + Version + Length)
	if len(buffer) < 5 {
		return false, nil
	}

	// 检查是否为TLS握手包 (Content Type = 0x16)
	if buffer[0] != 0x16 {
		// 不是TLS握手包，可能是其他协议或应用数据
		// 返回当前缓冲的所有数据
		return true, buffer
	}

	// 读取TLS记录长度 (字节3-4)
	recordLen := int(buffer[3])<<8 | int(buffer[4])

	// 完整TLS记录的总长度 = 5字节头 + 记录体长度
	totalLen := 5 + recordLen

	// 检查缓冲区是否包含完整记录
	if len(buffer) >= totalLen {
		// 返回完整的TLS记录
		return true, buffer[:totalLen]
	}

	// 数据不完整，继续等待
	return false, nil
}

// GetStreamStats 获取流统计信息
func (sr *StreamReassembler) GetStreamStats() map[string]interface{} {
	sr.mutex.RLock()
	defer sr.mutex.RUnlock()

	stats := map[string]interface{}{
		"active_streams": len(sr.streams),
		"streams":        make([]map[string]interface{}, 0),
	}

	for key, stream := range sr.streams {
		streamInfo := map[string]interface{}{
			"flow":        key.String(),
			"buffer_size": len(stream.Buffer),
			"age_seconds": time.Since(stream.LastActivity).Seconds(),
		}
		stats["streams"] = append(stats["streams"].([]map[string]interface{}), streamInfo)
	}

	return stats
}
