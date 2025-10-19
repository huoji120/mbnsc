package main

import (
	"sync"
	"time"
)

// ConnectionRecord 单次连接记录
type ConnectionRecord struct {
	Timestamp   time.Time `json:"timestamp"`
	LocalPort   string    `json:"local_port"`
	RemotePort  string    `json:"remote_port"`
	PacketSize  int       `json:"packet_size"`
	Direction   string    `json:"direction"` // "send" 或 "recv"
	Protocol    string    `json:"protocol"`
	TCPFlags    string    `json:"tcp_flags,omitempty"`
	IsTLS       bool      `json:"is_tls"`
	SNI         string    `json:"sni,omitempty"`
	ProcessName string    `json:"process_name,omitempty"`
}

// RemoteIPStats 远程IP的统计信息
type RemoteIPStats struct {
	RemoteIP     string                      `json:"remote_ip"`
	Records      []ConnectionRecord          `json:"records"`
	TotalPackets int                         `json:"total_packets"`
	TotalBytes   int64                       `json:"total_bytes"`
	SendPackets  int                         `json:"send_packets"`
	RecvPackets  int                         `json:"recv_packets"`
	SendBytes    int64                       `json:"send_bytes"`
	RecvBytes    int64                       `json:"recv_bytes"`
	FirstSeen    time.Time                   `json:"first_seen"`
	LastSeen     time.Time                   `json:"last_seen"`
	RemotePorts  map[string]int              `json:"remote_ports"`  // 远程端口 -> 使用次数
	LocalPorts   map[string]int              `json:"local_ports"`   // 本地端口 -> 使用次数
	SNINames     map[string]int              `json:"sni_names"`     // SNI域名 -> 使用次数
	DNSNames     map[string]int              `json:"dns_names"`     // DNS域名 -> 使用次数
	Processes    map[string]int              `json:"processes"`     // 进程名 -> 使用次数
	TLSCount     int                         `json:"tls_count"`     // TLS包数量
	Protocols    map[string]int              `json:"protocols"`     // 协议 -> 使用次数
}

// DataStore 数据存储层
type DataStore struct {
	stats    map[string]*RemoteIPStats
	dnsCache map[string][]string // IP -> DNS域名列表的缓存
	mutex    sync.RWMutex
}

// NewDataStore 创建数据存储
func NewDataStore() *DataStore {
	return &DataStore{
		stats:    make(map[string]*RemoteIPStats),
		dnsCache: make(map[string][]string),
	}
}

// Store 存储解析后的数据包信息
func (ds *DataStore) Store(info *PacketInfo) {
	if info.RemoteIP == "" {
		return
	}

	ds.mutex.Lock()
	defer ds.mutex.Unlock()

	// 获取或创建远程IP的统计信息
	stats, exists := ds.stats[info.RemoteIP]
	if !exists {
		stats = &RemoteIPStats{
			RemoteIP:    info.RemoteIP,
			Records:     make([]ConnectionRecord, 0),
			FirstSeen:   info.Timestamp,
			RemotePorts: make(map[string]int),
			LocalPorts:  make(map[string]int),
			SNINames:    make(map[string]int),
			DNSNames:    make(map[string]int),
			Processes:   make(map[string]int),
			Protocols:   make(map[string]int),
		}
		ds.stats[info.RemoteIP] = stats

		// 从DNS缓存中查找该IP的域名，并关联到新创建的统计记录
		if cachedDomains, hasDNS := ds.dnsCache[info.RemoteIP]; hasDNS {
			for _, domain := range cachedDomains {
				stats.DNSNames[domain]++
			}
		}
	}

	// 创建连接记录
	record := ConnectionRecord{
		Timestamp:   info.Timestamp,
		LocalPort:   info.LocalPort,
		RemotePort:  info.RemotePort,
		PacketSize:  info.Length,
		Direction:   info.Direction,
		Protocol:    info.Protocol,
		TCPFlags:    info.TCPFlags,
		IsTLS:       info.IsTLS,
		SNI:         info.SNI,
		ProcessName: info.ProcessName,
	}
	stats.Records = append(stats.Records, record)

	// 更新统计信息
	stats.TotalPackets++
	stats.TotalBytes += int64(info.Length)
	stats.LastSeen = info.Timestamp

	// 统计发送/接收
	if info.Direction == "send" {
		stats.SendPackets++
		stats.SendBytes += int64(info.Length)
	} else if info.Direction == "recv" {
		stats.RecvPackets++
		stats.RecvBytes += int64(info.Length)
	}

	// 统计端口
	if info.RemotePort != "" {
		stats.RemotePorts[info.RemotePort]++
	}
	if info.LocalPort != "" {
		stats.LocalPorts[info.LocalPort]++
	}

	// 统计SNI
	if info.SNI != "" {
		stats.SNINames[info.SNI]++
	}

	// 统计进程
	if info.ProcessName != "" {
		stats.Processes[info.ProcessName]++
	}

	// 统计TLS
	if info.IsTLS {
		stats.TLSCount++
	}

	// 统计协议
	if info.Protocol != "" {
		stats.Protocols[info.Protocol]++
	}

	// 处理DNS响应包：将DNS域名缓存到dnsCache，并尝试关联到已存在的IP
	if info.IsDNS && info.DNSQueryName != "" && len(info.DNSResponseIPs) > 0 {
		for _, responseIP := range info.DNSResponseIPs {
			// 1. 先将DNS域名缓存到dnsCache中
			if ds.dnsCache[responseIP] == nil {
				ds.dnsCache[responseIP] = make([]string, 0)
			}
			// 检查域名是否已经在缓存中，避免重复
			domainExists := false
			for _, cachedDomain := range ds.dnsCache[responseIP] {
				if cachedDomain == info.DNSQueryName {
					domainExists = true
					break
				}
			}
			if !domainExists {
				ds.dnsCache[responseIP] = append(ds.dnsCache[responseIP], info.DNSQueryName)
			}

			// 2. 如果该IP已经有统计记录，立即关联DNS域名
			if ipStats, exists := ds.stats[responseIP]; exists {
				if ipStats.DNSNames == nil {
					ipStats.DNSNames = make(map[string]int)
				}
				ipStats.DNSNames[info.DNSQueryName]++
			}
		}
	}
}

// GetStats 获取所有统计信息（只读）
func (ds *DataStore) GetStats() map[string]*RemoteIPStats {
	ds.mutex.RLock()
	defer ds.mutex.RUnlock()

	// 返回副本以避免并发问题
	result := make(map[string]*RemoteIPStats, len(ds.stats))
	for k, v := range ds.stats {
		result[k] = v
	}
	return result
}

// GetStatsForIP 获取指定IP的统计信息
func (ds *DataStore) GetStatsForIP(remoteIP string) *RemoteIPStats {
	ds.mutex.RLock()
	defer ds.mutex.RUnlock()

	return ds.stats[remoteIP]
}

// GetTotalPackets 获取总包数
func (ds *DataStore) GetTotalPackets() int {
	ds.mutex.RLock()
	defer ds.mutex.RUnlock()

	total := 0
	for _, stats := range ds.stats {
		total += stats.TotalPackets
	}
	return total
}

// GetTotalBytes 获取总字节数
func (ds *DataStore) GetTotalBytes() int64 {
	ds.mutex.RLock()
	defer ds.mutex.RUnlock()

	total := int64(0)
	for _, stats := range ds.stats {
		total += stats.TotalBytes
	}
	return total
}

// GetIPCount 获取不同IP数量
func (ds *DataStore) GetIPCount() int {
	ds.mutex.RLock()
	defer ds.mutex.RUnlock()

	return len(ds.stats)
}
