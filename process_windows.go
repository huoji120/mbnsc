// +build windows

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/windows"
)

var (
	modiphlpapi              = syscall.NewLazyDLL("iphlpapi.dll")
	procGetExtendedTcpTable  = modiphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable  = modiphlpapi.NewProc("GetExtendedUdpTable")
	modkernel32              = syscall.NewLazyDLL("kernel32.dll")
	procQueryFullProcessName = modkernel32.NewProc("QueryFullProcessImageNameW")
	modadvapi32              = syscall.NewLazyDLL("advapi32.dll")
	procOpenSCManagerW       = modadvapi32.NewProc("OpenSCManagerW")
	procOpenServiceW         = modadvapi32.NewProc("OpenServiceW")
	procQueryServiceStatusEx = modadvapi32.NewProc("QueryServiceStatusEx")
	procCloseServiceHandle   = modadvapi32.NewProc("CloseServiceHandle")
)

const (
	TCP_TABLE_OWNER_PID_ALL         = 5
	UDP_TABLE_OWNER_PID             = 1
	AF_INET                         = 2
	AF_INET6                        = 23
	SC_MANAGER_CONNECT              = 0x0001
	SERVICE_QUERY_STATUS            = 0x0004
	SC_STATUS_PROCESS_INFO          = 0
	SERVICE_RUNNING                 = 4
)

type MIB_TCPROW_OWNER_PID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPid  uint32
}

type MIB_UDPROW_OWNER_PID struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPid uint32
}

type SERVICE_STATUS_PROCESS struct {
	ServiceType             uint32
	CurrentState            uint32
	ControlsAccepted        uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
	CheckPoint              uint32
	WaitHint                uint32
	ProcessId               uint32
	ServiceFlags            uint32
}

type ProcessMonitor struct {
	tcpMap           map[string]uint32 // "IP:Port" -> PID
	udpMap           map[string]uint32 // "IP:Port" -> PID
	processName      map[uint32]string // PID -> ProcessName
	targetServicePID uint32            // 目标服务的 PID (如果设置)
	mutex            sync.RWMutex
	stopChan         chan struct{}
	running          bool
}

func NewProcessMonitor() *ProcessMonitor {
	return &ProcessMonitor{
		tcpMap:      make(map[string]uint32),
		udpMap:      make(map[string]uint32),
		processName: make(map[uint32]string),
		stopChan:    make(chan struct{}),
	}
}

func (pm *ProcessMonitor) Start() error {
	if pm.running {
		return nil
	}

	// 初始更新一次
	if err := pm.updateConnectionTable(); err != nil {
		return err
	}

	pm.running = true

	// 启动定期更新的goroutine (每秒更新一次)
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				pm.updateConnectionTable()
			case <-pm.stopChan:
				return
			}
		}
	}()

	return nil
}

func (pm *ProcessMonitor) Stop() {
	if !pm.running {
		return
	}
	pm.running = false
	close(pm.stopChan)
}

func (pm *ProcessMonitor) IsRunning() bool {
	return pm.running
}

func (pm *ProcessMonitor) updateConnectionTable() error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	// 清空旧数据
	pm.tcpMap = make(map[string]uint32)
	pm.udpMap = make(map[string]uint32)

	// 更新TCP连接表
	if err := pm.updateTcpTable(); err != nil {
		return fmt.Errorf("更新TCP表失败: %v", err)
	}

	// 更新UDP连接表
	if err := pm.updateUdpTable(); err != nil {
		return fmt.Errorf("更新UDP表失败: %v", err)
	}

	return nil
}

func (pm *ProcessMonitor) updateTcpTable() error {
	// 添加 panic 保护
	defer func() {
		if r := recover(); r != nil {
			// 记录错误但不中断程序
		}
	}()

	var size uint32 = 0

	// 第一次调用获取所需的缓冲区大小
	ret, _, _ := procGetExtendedTcpTable.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		0,
		AF_INET,
		TCP_TABLE_OWNER_PID_ALL,
		0,
	)

	if ret != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) && ret != 0 {
		return fmt.Errorf("GetExtendedTcpTable 失败: %d", ret)
	}

	// 分配缓冲区
	buffer := make([]byte, size)
	ret, _, _ = procGetExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
		AF_INET,
		TCP_TABLE_OWNER_PID_ALL,
		0,
	)

	if ret != 0 {
		return fmt.Errorf("GetExtendedTcpTable 失败: %d", ret)
	}

	// 解析TCP表
	numEntries := binary.LittleEndian.Uint32(buffer[0:4])
	offset := 4

	for i := uint32(0); i < numEntries; i++ {
		if offset+24 > len(buffer) {
			break
		}

		row := (*MIB_TCPROW_OWNER_PID)(unsafe.Pointer(&buffer[offset]))
		offset += 24 // sizeof(MIB_TCPROW_OWNER_PID)

		// 转换端口字节序
		localPort := ntohs(uint16(row.LocalPort))
		localIP := intToIP(row.LocalAddr)

		key := fmt.Sprintf("%s:%d", localIP, localPort)
		pm.tcpMap[key] = row.OwningPid

		// 延迟获取进程名，只在需要时获取
		// 这里只记录 PID，不立即查询进程名
	}

	return nil
}

func (pm *ProcessMonitor) updateUdpTable() error {
	// 添加 panic 保护
	defer func() {
		if r := recover(); r != nil {
			// 记录错误但不中断程序
		}
	}()

	var size uint32 = 0

	// 第一次调用获取所需的缓冲区大小
	ret, _, _ := procGetExtendedUdpTable.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		0,
		AF_INET,
		UDP_TABLE_OWNER_PID,
		0,
	)

	if ret != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) && ret != 0 {
		return fmt.Errorf("GetExtendedUdpTable 失败: %d", ret)
	}

	// 分配缓冲区
	buffer := make([]byte, size)
	ret, _, _ = procGetExtendedUdpTable.Call(
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
		AF_INET,
		UDP_TABLE_OWNER_PID,
		0,
	)

	if ret != 0 {
		return fmt.Errorf("GetExtendedUdpTable 失败: %d", ret)
	}

	// 解析UDP表
	numEntries := binary.LittleEndian.Uint32(buffer[0:4])
	offset := 4

	for i := uint32(0); i < numEntries; i++ {
		if offset+12 > len(buffer) {
			break
		}

		row := (*MIB_UDPROW_OWNER_PID)(unsafe.Pointer(&buffer[offset]))
		offset += 12 // sizeof(MIB_UDPROW_OWNER_PID)

		// 转换端口字节序
		localPort := ntohs(uint16(row.LocalPort))
		localIP := intToIP(row.LocalAddr)

		key := fmt.Sprintf("%s:%d", localIP, localPort)
		pm.udpMap[key] = row.OwningPid

		// 延迟获取进程名，只在需要时获取
		// 这里只记录 PID，不立即查询进程名
	}

	return nil
}

func (pm *ProcessMonitor) GetProcessNameForPacket(packet gopacket.Packet) string {
	var srcIP, dstIP net.IP
	var srcPort, dstPort uint16
	var isTCP bool

	// 解析IP层
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		srcIP = ip.SrcIP
		dstIP = ip.DstIP
	} else {
		return ""
	}

	// 解析传输层
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		srcPort = uint16(tcp.SrcPort)
		dstPort = uint16(tcp.DstPort)
		isTCP = true
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		srcPort = uint16(udp.SrcPort)
		dstPort = uint16(udp.DstPort)
		isTCP = false
	} else {
		return ""
	}

	// 查找本地端口对应的进程
	// 优先查找源端口（本地发送的包）
	srcKey := fmt.Sprintf("%s:%d", srcIP, srcPort)
	dstKey := fmt.Sprintf("%s:%d", dstIP, dstPort)

	pm.mutex.RLock()
	var pid uint32
	if isTCP {
		if p, ok := pm.tcpMap[srcKey]; ok {
			pid = p
		} else if p, ok := pm.tcpMap[dstKey]; ok {
			pid = p
		}
	} else {
		if p, ok := pm.udpMap[srcKey]; ok {
			pid = p
		} else if p, ok := pm.udpMap[dstKey]; ok {
			pid = p
		}
	}

	if pid == 0 {
		pm.mutex.RUnlock()
		return ""
	}

	// 先检查缓存
	if name, ok := pm.processName[pid]; ok {
		pm.mutex.RUnlock()
		return name
	}
	pm.mutex.RUnlock()

	// 缓存中没有，尝试获取进程名
	name := getProcessName(pid)
	if name != "" {
		// 更新缓存
		pm.mutex.Lock()
		pm.processName[pid] = name
		pm.mutex.Unlock()
		return name
	}

	return fmt.Sprintf("PID:%d", pid)
}

// 辅助函数

func ntohs(port uint16) uint16 {
	return (port>>8)&0xff | (port<<8)&0xff00
}

func intToIP(ipInt uint32) string {
	return net.IPv4(byte(ipInt), byte(ipInt>>8), byte(ipInt>>16), byte(ipInt>>24)).String()
}

func getProcessName(pid uint32) string {
	// 添加 panic 保护
	defer func() {
		if r := recover(); r != nil {
			// 静默恢复，某些进程可能无法访问
		}
	}()

	if pid == 0 {
		return "System"
	}

	if pid == 4 {
		return "System"
	}

	// 打开进程句柄
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}

	// 检查句柄是否有效
	if handle == 0 || handle == windows.InvalidHandle {
		return ""
	}

	defer windows.CloseHandle(handle)

	// 使用更大的缓冲区
	var size uint32 = 32768 // 使用更大的缓冲区
	buf := make([]uint16, size)

	// 调用 Windows API
	ret, _, err := procQueryFullProcessName.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
	)

	if ret == 0 {
		// 失败时尝试使用备用方法
		return getProcessNameFallback(pid)
	}

	if size == 0 || size > uint32(len(buf)) {
		return ""
	}

	fullPath := syscall.UTF16ToString(buf[:size])

	if fullPath == "" {
		return ""
	}

	// 只返回文件名部分
	for i := len(fullPath) - 1; i >= 0; i-- {
		if fullPath[i] == '\\' || fullPath[i] == '/' {
			return fullPath[i+1:]
		}
	}

	return fullPath
}

// 备用方法：使用 Process32First/Process32Next
func getProcessNameFallback(pid uint32) string {
	// 简单返回 PID，避免更复杂的调用
	return fmt.Sprintf("PID:%d", pid)
}
