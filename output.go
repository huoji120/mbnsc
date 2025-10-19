package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// OutputFormatter 输出格式化器
type OutputFormatter struct {
	verbose bool // 是否输出详细信息
}

// NewOutputFormatter 创建输出格式化器
func NewOutputFormatter(verbose bool) *OutputFormatter {
	return &OutputFormatter{
		verbose: verbose,
	}
}

// PrintPacket 实时打印数据包信息
func (of *OutputFormatter) PrintPacket(info *PacketInfo) {

	timestamp := info.Timestamp.Format("15:04:05.000000")
	output := fmt.Sprintf("[%s] %s %s:%s -> %s:%s",
		timestamp,
		info.Protocol,
		info.SrcIP, info.SrcPort,
		info.DstIP, info.DstPort)

	if info.TCPFlags != "" {
		output += fmt.Sprintf(" [%s]", info.TCPFlags)
	}

	output += fmt.Sprintf(" Len:%d", info.Length)

	if info.ProcessName != "" {
		output += fmt.Sprintf(" [%s]", info.ProcessName)
	}

	if info.IsTLS {
		output += " [TLS"
		if info.TLSVersion != "" {
			output += " " + info.TLSVersion
		}
		output += "]"
	}

	if info.SNI != "" {
		output += fmt.Sprintf(" SNI: %s", info.SNI)
	}
	if info.IsDNS {
		output += fmt.Sprintf(" Dns: %s", info.DNSQueryName)

	}
	fmt.Println(output)
}

// PrintStats 打印统计信息
func (of *OutputFormatter) PrintStats(dataStore *DataStore) {
	stats := dataStore.GetStats()

	fmt.Println("\n" + strings.Repeat("=", 100))
	fmt.Println("远程IP交互统计报告")
	fmt.Println(strings.Repeat("=", 100))

	if len(stats) == 0 {
		fmt.Println("没有记录到任何远程IP交互")
		return
	}

	// 按IP排序
	ips := make([]string, 0, len(stats))
	for ip := range stats {
		ips = append(ips, ip)
	}
	sort.Strings(ips)

	totalBytes := int64(0)
	totalPackets := 0

	for _, ip := range ips {
		s := stats[ip]
		totalBytes += s.TotalBytes
		totalPackets += s.TotalPackets

		of.printIPStats(s)
	}

	// 总体统计
	fmt.Println("\n" + strings.Repeat("=", 100))
	fmt.Printf("总体统计:\n")
	fmt.Printf("  不同的远程IP数: %d\n", len(stats))
	fmt.Printf("  总数据包数: %d\n", totalPackets)
	fmt.Printf("  总数据量: %s\n", formatBytes(totalBytes))
	fmt.Println(strings.Repeat("=", 100))
}

// printIPStats 打印单个IP的统计信息
func (of *OutputFormatter) printIPStats(s *RemoteIPStats) {
	fmt.Printf("\n远程IP: %s\n", s.RemoteIP)
	fmt.Println(strings.Repeat("-", 100))
	fmt.Printf("  总数据包数: %d (发送: %d, 接收: %d)\n",
		s.TotalPackets, s.SendPackets, s.RecvPackets)
	fmt.Printf("  总数据量: %s (发送: %s, 接收: %s)\n",
		formatBytes(s.TotalBytes), formatBytes(s.SendBytes), formatBytes(s.RecvBytes))
	fmt.Printf("  首次交互: %s\n", s.FirstSeen.Format("2006-01-02 15:04:05.000"))
	fmt.Printf("  最后交互: %s\n", s.LastSeen.Format("2006-01-02 15:04:05.000"))
	fmt.Printf("  交互时长: %s\n", s.LastSeen.Sub(s.FirstSeen).Round(time.Millisecond))

	// 显示协议统计
	if len(s.Protocols) > 0 {
		fmt.Print("  协议统计: ")
		protoList := make([]string, 0)
		for proto, count := range s.Protocols {
			protoList = append(protoList, fmt.Sprintf("%s(%d)", proto, count))
		}
		sort.Strings(protoList)
		fmt.Println(strings.Join(protoList, ", "))
	}

	// 显示TLS统计
	if s.TLSCount > 0 {
		fmt.Printf("  TLS包数量: %d\n", s.TLSCount)
	}

	// 显示使用的远程端口
	if len(s.RemotePorts) > 0 {
		fmt.Print("  远程端口: ")
		portList := make([]string, 0)
		for port, count := range s.RemotePorts {
			portList = append(portList, fmt.Sprintf("%s(%d)", port, count))
		}
		sort.Strings(portList)
		fmt.Println(strings.Join(portList, ", "))
	}

	// 显示使用的本地端口
	if len(s.LocalPorts) > 0 {
		fmt.Print("  本地端口: ")
		portList := make([]string, 0)
		for port, count := range s.LocalPorts {
			portList = append(portList, fmt.Sprintf("%s(%d)", port, count))
		}
		sort.Strings(portList)
		fmt.Println(strings.Join(portList, ", "))
	}

	// 显示SNI域名
	if len(s.SNINames) > 0 {
		fmt.Print("  SNI域名: ")
		sniList := make([]string, 0)
		for sni, count := range s.SNINames {
			sniList = append(sniList, fmt.Sprintf("%s(%d)", sni, count))
		}
		sort.Strings(sniList)
		fmt.Println(strings.Join(sniList, ", "))
	}

	// 显示进程统计
	if len(s.Processes) > 0 {
		fmt.Print("  进程统计: ")
		procList := make([]string, 0)
		for proc, count := range s.Processes {
			procList = append(procList, fmt.Sprintf("%s(%d)", proc, count))
		}
		sort.Strings(procList)
		fmt.Println(strings.Join(procList, ", "))
	}

	// 显示详细的交互记录（前10条和后10条）
	if of.verbose {
		of.printRecords(s.Records)
	}
}

// printRecords 打印连接记录
func (of *OutputFormatter) printRecords(records []ConnectionRecord) {
	fmt.Println("\n  交互记录:")
	recordCount := len(records)
	displayCount := 10

	if recordCount <= displayCount*2 {
		// 记录数少，全部显示
		for i, record := range records {
			of.printRecord(i+1, &record)
		}
	} else {
		// 记录数多，显示前10条
		for i := 0; i < displayCount; i++ {
			of.printRecord(i+1, &records[i])
		}
		fmt.Printf("    ... (省略 %d 条记录) ...\n", recordCount-displayCount*2)
		// 显示后10条
		for i := recordCount - displayCount; i < recordCount; i++ {
			of.printRecord(i+1, &records[i])
		}
	}
}

// printRecord 打印单条记录
func (of *OutputFormatter) printRecord(index int, record *ConnectionRecord) {
	output := fmt.Sprintf("    [%d] %s | %s | %s | 本地:%s 远程:%s | 大小:%d字节",
		index,
		record.Timestamp.Format("15:04:05.000000"),
		record.Direction,
		record.Protocol,
		record.LocalPort,
		record.RemotePort,
		record.PacketSize)

	if record.TCPFlags != "" {
		output += fmt.Sprintf(" | Flags:%s", record.TCPFlags)
	}

	if record.IsTLS {
		output += " | TLS"
	}

	if record.SNI != "" {
		output += fmt.Sprintf(" | SNI:%s", record.SNI)
	}

	if record.ProcessName != "" {
		output += fmt.Sprintf(" | [%s]", record.ProcessName)
	}

	fmt.Println(output)
}

// SaveToJSON 保存统计数据为JSON文件
func (of *OutputFormatter) SaveToJSON(dataStore *DataStore, filename string) error {
	stats := dataStore.GetStats()

	// 创建JSON文件
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("创建JSON文件失败: %v", err)
	}
	defer file.Close()

	// 创建JSON编码器，使用美化格式
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	// 将统计数据编码为JSON
	if err := encoder.Encode(stats); err != nil {
		return fmt.Errorf("编码JSON失败: %v", err)
	}

	return nil
}

// formatBytes 格式化字节数为可读形式
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
