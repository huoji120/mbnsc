package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

var (
	device         string
	snapshotLen    int32         = 1600
	promiscuous    bool          = false
	timeout        time.Duration = 30 * time.Second
	filter         string
	excludeProcess string // 排除的进程名，逗号分隔
	includeProcess string // 只包含的进程名，逗号分隔
	serviceName    string // 指定服务名，如 SharedAccess (ICS服务)
	listDevices    bool
	saveToFile     string
)

func init() {
	flag.StringVar(&device, "i", "", "指定网络接口，如果不指定则列出所有网卡")
	flag.StringVar(&filter, "f", "", "BPF过滤器表达式")
	flag.StringVar(&excludeProcess, "exclude", "", "排除的进程名（逗号分隔），例如: chrome.exe,firefox.exe")
	flag.StringVar(&includeProcess, "include", "", "只包含的进程名（逗号分隔），例如: python.exe")
	flag.StringVar(&serviceName, "service", "", "只显示指定Windows服务的流量，例如: SharedAccess (ICS服务)")
	flag.BoolVar(&listDevices, "l", false, "列出所有网络接口")
	flag.StringVar(&saveToFile, "w", "", "保存抓包结果到pcap文件")
}

func main() {
	flag.Parse()

	// 列出所有网卡
	if listDevices || device == "" {
		if err := listAllDevices(); err != nil {
			log.Fatal(err)
		}
		if device == "" {
			return
		}
	}

	// 初始化新架构的组件
	parser := NewPacketParser()
	defer parser.Stop() // 清理流重组器资源
	dataStore := NewDataStore()
	output := NewOutputFormatter(true) // verbose模式

	// 初始化进程监控
	pm := NewProcessMonitor()
	if err := pm.Start(); err != nil {
		log.Printf("警告: 进程监控启动失败: %v", err)
		log.Printf("将无法进行进程过滤")
	}
	defer pm.Stop()

	// 解析进程过滤规则
	var excludeList, includeList []string
	var servicePID uint32

	// 如果指定了服务名，获取服务的 PID
	if serviceName != "" {
		pid, err := GetServicePID(serviceName)
		if err != nil {
			log.Fatalf("无法获取服务 '%s' 的PID: %v", serviceName, err)
		}
		servicePID = pid
		log.Printf("服务 '%s' 运行在 PID: %d", serviceName, servicePID)

		// 设置进程监控器追踪这个 PID
		pm.SetTargetServicePID(servicePID)
	}

	if excludeProcess != "" {
		excludeList = strings.Split(excludeProcess, ",")
		for i := range excludeList {
			excludeList[i] = strings.TrimSpace(excludeList[i])
		}
		log.Printf("排除进程: %v", excludeList)
	}
	if includeProcess != "" {
		includeList = strings.Split(includeProcess, ",")
		for i := range includeList {
			includeList[i] = strings.TrimSpace(includeList[i])
		}
		log.Printf("只包含进程: %v", includeList)
	}

	// 打开网卡
	handle, err := pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// 设置BPF过滤器
	if filter != "" {
		if err := handle.SetBPFFilter(filter); err != nil {
			log.Fatal(err)
		}
		log.Printf("应用BPF过滤器: %s", filter)
	}

	// 创建pcap写入器（如果需要保存文件）
	var pcapWriter *pcapgo.Writer
	if saveToFile != "" {
		f, err := os.Create(saveToFile)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		pcapWriter = pcapgo.NewWriter(f)
		pcapWriter.WriteFileHeader(uint32(snapshotLen), handle.LinkType())
		log.Printf("保存抓包结果到: %s", saveToFile)
	}

	log.Printf("开始在 %s 上抓包...", device)
	log.Printf("按 Ctrl+C 停止")

	// 处理Ctrl+C信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetChan := packetSource.Packets()

	packetCount := 0
	filteredCount := 0

	for {
		select {
		case <-sigChan:
			log.Printf("\n总共捕获: %d 个包", packetCount)
			log.Printf("过滤后显示: %d 个包", filteredCount)

			// 使用新的输出格式化器打印统计信息
			output.PrintStats(dataStore)

			// 保存统计数据为JSON文件
			jsonFilename := fmt.Sprintf("capture_stats_%s.json", time.Now().Format("20060102_150405"))
			if err := output.SaveToJSON(dataStore, jsonFilename); err != nil {
				log.Printf("保存JSON文件失败: %v", err)
			} else {
				log.Printf("\n统计数据已保存到: %s", jsonFilename)
			}
			return
		case packet := <-packetChan:
			packetCount++

			// 新架构：流量 -> 合包（流重组） -> 解包 -> 数据存储 -> 输出

			// 1. 解析数据包（包含TCP流重组）
			packetInfo := parser.Parse(packet)

			// 如果返回nil，说明数据包正在缓冲中（等待更多分片）
			if packetInfo == nil {
				continue
			}

			// 2. 获取进程信息（如果进程监控在运行）
			if pm.IsRunning() {
				packetInfo.ProcessName, packetInfo.ProcessPID = pm.GetProcessInfoForPacket(packet)
			}

			// 3. 检查是否需要根据进程过滤
			shouldDisplay := true

			// 如果指定了服务，只显示该服务的流量
			if servicePID != 0 {
				shouldDisplay = (packetInfo.ProcessPID == servicePID)
			} else {
				// 如果设置了include列表，只显示在列表中的进程
				if len(includeList) > 0 {
					shouldDisplay = false
					for _, name := range includeList {
						if strings.EqualFold(packetInfo.ProcessName, name) {
							shouldDisplay = true
							break
						}
					}
				}

				// 如果设置了exclude列表，排除列表中的进程
				if len(excludeList) > 0 && shouldDisplay {
					for _, name := range excludeList {
						if strings.EqualFold(packetInfo.ProcessName, name) {
							shouldDisplay = false
							break
						}
					}
				}
			}

			if shouldDisplay {
				filteredCount++

				// 4. 存储数据
				dataStore.Store(packetInfo)

				// 5. 输出（仅显示有SNI的TLS包）
				output.PrintPacket(packetInfo)

				// 保存到文件
				if pcapWriter != nil {
					if err := pcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
						log.Printf("写入pcap文件失败: %v", err)
					}
				}
			}
		}
	}
}

func listAllDevices() error {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return err
	}

	fmt.Println("\n可用的网络接口:")
	fmt.Println(strings.Repeat("-", 80))
	for i, device := range devices {
		fmt.Printf("%d. %s\n", i+1, device.Name)
		if device.Description != "" {
			fmt.Printf("   描述: %s\n", device.Description)
		}

		if len(device.Addresses) > 0 {
			fmt.Printf("   地址: ")
			for j, address := range device.Addresses {
				if j > 0 {
					fmt.Printf("         ")
				}
				fmt.Printf("IP: %s", address.IP)
				if address.Netmask != nil {
					fmt.Printf("  掩码: %s", address.Netmask)
				}
				fmt.Println()
			}
		}
		fmt.Println()
	}
	fmt.Println(strings.Repeat("-", 80))
	fmt.Printf("使用 -i <接口名> 来指定要监听的网卡\n")
	fmt.Printf("例如: %s -i %s\n", os.Args[0], devices[0].Name)
	fmt.Println()

	return nil
}
