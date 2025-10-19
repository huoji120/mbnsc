// +build windows

package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// SetTargetServicePID 设置目标服务的 PID
func (pm *ProcessMonitor) SetTargetServicePID(pid uint32) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()
	pm.targetServicePID = pid
}

// GetProcessInfoForPacket 返回包对应的进程名和PID
func (pm *ProcessMonitor) GetProcessInfoForPacket(packet gopacket.Packet) (string, uint32) {
	var srcIP, dstIP string
	var srcPort, dstPort uint16
	var isTCP bool

	// 解析IP层
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
	} else {
		return "", 0
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
		return "", 0
	}

	// 查找本地端口对应的进程
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
		return "", 0
	}

	// 先检查缓存
	if name, ok := pm.processName[pid]; ok {
		pm.mutex.RUnlock()
		return name, pid
	}
	pm.mutex.RUnlock()

	// 缓存中没有，尝试获取进程名
	name := getProcessName(pid)
	if name != "" {
		// 更新缓存
		pm.mutex.Lock()
		pm.processName[pid] = name
		pm.mutex.Unlock()
		return name, pid
	}

	return fmt.Sprintf("PID:%d", pid), pid
}

// GetServicePID 获取指定服务的 PID
func GetServicePID(serviceName string) (uint32, error) {
	// 打开服务控制管理器
	scManager, _, err := procOpenSCManagerW.Call(
		0,
		0,
		SC_MANAGER_CONNECT,
	)
	if scManager == 0 {
		return 0, fmt.Errorf("无法打开服务控制管理器: %v", err)
	}
	defer procCloseServiceHandle.Call(scManager)

	// 转换服务名为 UTF16
	serviceNameUTF16, err := syscall.UTF16PtrFromString(serviceName)
	if err != nil {
		return 0, fmt.Errorf("服务名转换失败: %v", err)
	}

	// 打开服务
	service, _, err := procOpenServiceW.Call(
		scManager,
		uintptr(unsafe.Pointer(serviceNameUTF16)),
		SERVICE_QUERY_STATUS,
	)
	if service == 0 {
		return 0, fmt.Errorf("无法打开服务 '%s': %v (服务可能未运行)", serviceName, err)
	}
	defer procCloseServiceHandle.Call(service)

	// 查询服务状态
	var status SERVICE_STATUS_PROCESS
	var bytesNeeded uint32
	ret, _, err := procQueryServiceStatusEx.Call(
		service,
		SC_STATUS_PROCESS_INFO,
		uintptr(unsafe.Pointer(&status)),
		unsafe.Sizeof(status),
		uintptr(unsafe.Pointer(&bytesNeeded)),
	)

	if ret == 0 {
		return 0, fmt.Errorf("查询服务状态失败: %v", err)
	}

	if status.ProcessId == 0 {
		return 0, fmt.Errorf("服务 '%s' 未运行", serviceName)
	}

	return status.ProcessId, nil
}
