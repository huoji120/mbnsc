# MB Capture - C2流量检测工具

[![Go Version](https://img.shields.io/badge/Go-1.20+-blue.svg)](https://golang.org)
[![Python Version](https://img.shields.io/badge/Python-3.6+-green.svg)](https://www.python.org)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)]()

> 专业的网络流量捕获和C2恶意软件通信检测工具

**MB Capture** 是一个先进的网络安全工具，专门用于检测潜在的命令与控制(C2)恶意软件通信。它结合了实时网络数据包捕获和智能流量模式分析，能够识别出常规网络监控工具难以发现的隐蔽通信行为。

## ✨ 核心特性

### 🔍 实时流量捕获
- **高性能数据包捕获**: 基于libpcap的实时网络监控
- **TCP流重组**: 智能处理分片和乱序数据包
- **进程关联**: 将网络流量与具体进程关联
- **多协议支持**: TCP/UDP/HTTP/HTTPS/DNS等协议解析
- **TLS/SSL检测**: 支持SNI提取和加密流量分析

### 🤖 智能C2检测
- **周期性通信检测**: 使用变异系数算法识别规律性通信
- **行为模式分析**: 基于统计学方法的异常流量识别
- **威胁情报集成**: 支持OTX(AlienVault)威胁情报查询
- **时间序列分析**: 流量时间模式可视化分析

### 📊 可视化报告
- **交互式HTML报告**: 基于Chart.js的动态图表
- **详细统计信息**: 连接数、数据量、协议分布等
- **时间序列图表**: 流量模式可视化展示
- **威胁评估报告**: 可疑IP的风险等级评估

### 🎯 精准过滤
- **进程过滤**: 基于进程名称的包含/排除过滤
- **BPF过滤器**: 支持标准BPF语法过滤规则
- **网卡选择**: 多网卡环境下的精确选择
- **协议过滤**: 按协议类型进行数据筛选

## 🚀 快速开始

### 环境要求

- **Windows 10/11** (主要支持平台)
- **Go 1.20+** (用于编译抓包工具)
- **Python 3.6+** (用于流量分析)
- **管理员权限** (用于网络数据包捕获)

### 30秒快速测试

```bash
# 1. 生成测试数据
python generate_test_data.py

# 2. 运行分析
python analyzer.py test_capture_stats.json

# 3. 查看报告
start traffic_report.html   # Windows
```

### 完整使用流程

#### 步骤1: 编译工具

```bash
git clone https://github.com/huoji120/mbnsc.git
cd mbnsc
go build -o mbnsc.exe main.go
```

#### 步骤2: 捕获流量

```bash
# 列出可用网卡
mbnsc.exe -l

# 开始捕获 (建议10-30分钟)
mbnsc.exe -i "你的网卡名称"

# 按 Ctrl+C 停止，自动生成统计文件
```

#### 步骤3: 分析数据

```bash
# 使用默认设置分析
python analyzer.py capture_stats_20241019_143022.json

# 自定义输出文件
python analyzer.py capture_stats_20241019_143022.json -o my_report.html
```

## 📖 详细用法

### 命令行选项

#### 抓包工具 (mbnsc.exe)

```bash
mbnsc.exe [选项]

选项:
  -i string     指定网卡名称 (必需)
  -l            列出所有可用网卡
  -include string   只监控指定进程 (逗号分隔)
  -exclude string   排除指定进程 (逗号分隔)
  -bpf string       BPF过滤表达式
  -pcap string      保存原始数据包到PCAP文件
  -stats string     指定统计文件输出路径
  -duration int     捕获持续时间(秒)
  -v               显示详细输出
  -q               静默模式
```

#### 分析工具 (analyzer.py)

```bash
python analyzer.py [输入文件] [选项]

选项:
  -o, --output FILE      指定输出HTML文件名
  -t, --tolerance FLOAT  设置检测容差 (默认: 0.3)
  --threat-intel         启用威胁情报查询
  --threads NUM          设置分析线程数
  --help                 显示帮助信息
```

### 使用场景示例

#### 场景1: 监控手机流量

```bash
# 手机连接电脑WiFi热点后
mbnsc.exe -i "本地连接* 12"  # 选择WiFi热点网卡
# 等待30分钟后按 Ctrl+C
python analyzer.py capture_stats_*.json
```

#### 场景2: 监控特定进程

```bash
# 只监控可疑程序
mbnsc.exe -i "以太网" -include "suspicious.exe"
python analyzer.py capture_stats_*.json
```

#### 场景3: 排除已知程序

```bash
# 排除浏览器等正常程序
mbnsc.exe -i "以太网" -exclude "chrome.exe,firefox.exe,wechat.exe"
python analyzer.py capture_stats_*.json
```

## 📊 报告解读

### 🔴 高度可疑特征

1. **变异系数 < 0.1**: 通信极度规律，像机器设定的定时任务
2. **无DNS/SNI信息**: 直接使用IP通讯，没有域名关联
3. **未知进程**: ProcessName为空，可能是隐蔽进程
4. **典型C2周期 (30-120秒)**: 常见的C2心跳间隔

### 🟡 需要关注特征

1. **可疑域名**: 随机字符、新注册或伪装的CDN域名
2. **伪装进程**: 名为svchost.exe但行为异常
3. **不规律但有规律**: 整体不规律但局部有规律性

### 🟢 可能为误报

1. **知名服务**: Google、Microsoft、Apple等大公司服务
2. **变异系数接近阈值**: 可能是正常但较规律的服务

## 🛠️ 高级配置

### 调优检测参数

```bash
# 提高灵敏度 (减少漏报)
python analyzer.py data.json --tolerance 0.2

# 降低误报率
python analyzer.py data.json --tolerance 0.4
```

### BPF过滤示例

```bash
# 只捕获HTTP/HTTPS流量
mbnsc.exe -i "网卡" -bpf "tcp port 80 or tcp port 443"

# 排除内网流量
mbnsc.exe -i "网卡" -bpf "not net 192.168.0.0/16 and not net 10.0.0.0/8"

# 监控特定IP
mbnsc.exe -i "网卡" -bpf "host 192.168.1.100"
```

## 📁 项目结构

```
mbnsc/
├── main.go                 # 主程序入口和捕获循环
├── parser.go              # 协议解析模块
├── stream_reassembler.go  # TCP流重组
├── store.go               # 数据存储管理
├── output.go              # 实时输出格式化
├── process_windows.go     # Windows进程监控
├── service_windows.go     # Windows服务监控
├── analyzer.py            # 流量分析引擎
├── generate_test_data.py  # 测试数据生成器
├── QUICKSTART.md          # 快速开始指南 (中文)
├── ANALYZER_README.md     # 分析器详细文档
├── go.mod                 # Go模块依赖
└── README.md              # 本文档
```

## 🤝 贡献指南

欢迎提交Issue和Pull Request！

### 开发环境设置

```bash
# 克隆项目
git clone https://github.com/huoij120/mbnsc.git
cd mbnsc

# 安装Go依赖
go mod tidy

# 编译调试版本
go build -ldflags="-X main.debug=true" -o mbnsc_debug.exe

# 运行测试
go test ./...
```

### 代码风格

- Go代码遵循标准Go格式化规范
- Python代码遵循PEP 8规范
- 提交前请运行格式化工具

## ⚠️ 免责声明

- 本工具仅供**防御性安全分析**使用
- 请勿用于未授权的网络监控
- 检测结果仅供参考，需结合其他信息判断
- 使用者需确保符合当地法律法规

## 📄 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情

## 🙏 致谢

- [gopacket](https://github.com/google/gopacket) - Go语言数据包捕获库
- [Chart.js](https://www.chartjs.org/) - 数据可视化图表库
- [AlienVault OTX](https://otx.alienvault.com/) - 威胁情报数据源


**⭐ 如果这个项目对您有帮助，请给我们一个Star！**
