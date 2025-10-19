#!/usr/bin/env python3
"""
测试数据生成器
生成模拟的网络流量JSON数据，用于测试分析工具
"""

import json
import random
from datetime import datetime, timedelta


def generate_normal_traffic(ip, start_time, count=20):
    """生成正常的不规律流量"""
    records = []
    current_time = start_time

    for i in range(count):
        # 随机间隔: 1-60秒
        interval = random.uniform(1, 60)
        current_time += timedelta(seconds=interval)

        record = {
            "timestamp": current_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "packet_size": random.randint(100, 5000),
            "direction": random.choice(["send", "recv"]),
            "protocol": "TCP",
            "local_port": str(random.randint(50000, 60000)),
            "remote_port": "443",
            "is_tls": True,
            "sni": "normal-service.com",
            "process_name": "chrome.exe"
        }
        records.append(record)

    return records


def generate_c2_traffic(ip, start_time, period=60, count=30):
    """生成周期性的C2流量"""
    records = []
    current_time = start_time

    for i in range(count):
        # 周期性间隔，带少量jitter
        jitter = random.uniform(-period * 0.1, period * 0.1)  # ±10% jitter
        interval = period + jitter
        current_time += timedelta(seconds=interval)

        # 心跳包通常很小
        packet_size = random.randint(50, 200) if i % 3 == 0 else random.randint(200, 1000)

        record = {
            "timestamp": current_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "packet_size": packet_size,
            "direction": "send" if i % 2 == 0 else "recv",
            "protocol": "TCP",
            "local_port": str(random.randint(50000, 60000)),
            "remote_port": "8080",
            "is_tls": False,
            "sni": "",
            "process_name": ""  # 未知进程
        }
        records.append(record)

    return records


def generate_test_json():
    """生成测试JSON数据"""
    start_time = datetime.now() - timedelta(hours=1)

    data = {}

    # 1. 正常流量 - Google服务器
    records = generate_normal_traffic("142.250.185.46", start_time, count=30)
    data["142.250.185.46"] = {
        "remote_ip": "142.250.185.46",
        "records": records,
        "total_packets": len(records),
        "total_bytes": sum(r["packet_size"] for r in records),
        "send_packets": sum(1 for r in records if r["direction"] == "send"),
        "recv_packets": sum(1 for r in records if r["direction"] == "recv"),
        "send_bytes": sum(r["packet_size"] for r in records if r["direction"] == "send"),
        "recv_bytes": sum(r["packet_size"] for r in records if r["direction"] == "recv"),
        "first_seen": records[0]["timestamp"],
        "last_seen": records[-1]["timestamp"],
        "remote_ports": {"443": len(records)},
        "local_ports": {r["local_port"]: 1 for r in records},
        "sni_names": {"normal-service.com": 15, "www.google.com": 10},
        "dns_names": {"www.google.com": 1},
        "processes": {"chrome.exe": len(records)},
        "tls_count": len(records),
        "protocols": {"TCP": len(records)}
    }

    # 2. 可疑C2流量 - 每60秒通讯
    records = generate_c2_traffic("185.220.101.42", start_time, period=60, count=40)
    data["185.220.101.42"] = {
        "remote_ip": "185.220.101.42",
        "records": records,
        "total_packets": len(records),
        "total_bytes": sum(r["packet_size"] for r in records),
        "send_packets": sum(1 for r in records if r["direction"] == "send"),
        "recv_packets": sum(1 for r in records if r["direction"] == "recv"),
        "send_bytes": sum(r["packet_size"] for r in records if r["direction"] == "send"),
        "recv_bytes": sum(r["packet_size"] for r in records if r["direction"] == "recv"),
        "first_seen": records[0]["timestamp"],
        "last_seen": records[-1]["timestamp"],
        "remote_ports": {"8080": len(records)},
        "local_ports": {r["local_port"]: 1 for r in records},
        "sni_names": {},
        "dns_names": {},
        "processes": {"": len(records)},  # 未知进程
        "tls_count": 0,
        "protocols": {"TCP": len(records)}
    }

    # 3. 另一个可疑C2流量 - 每45秒通讯（更快）
    records = generate_c2_traffic("198.54.132.88", start_time, period=45, count=50)
    data["198.54.132.88"] = {
        "remote_ip": "198.54.132.88",
        "records": records,
        "total_packets": len(records),
        "total_bytes": sum(r["packet_size"] for r in records),
        "send_packets": sum(1 for r in records if r["direction"] == "send"),
        "recv_packets": sum(1 for r in records if r["direction"] == "recv"),
        "send_bytes": sum(r["packet_size"] for r in records if r["direction"] == "send"),
        "recv_bytes": sum(r["packet_size"] for r in records if r["direction"] == "recv"),
        "first_seen": records[0]["timestamp"],
        "last_seen": records[-1]["timestamp"],
        "remote_ports": {"443": len(records)},  # 伪装成HTTPS
        "local_ports": {r["local_port"]: 1 for r in records},
        "sni_names": {"cdn.example.net": 5},  # 伪造的SNI
        "dns_names": {"cdn.example.net": 1},
        "processes": {"svchost.exe": len(records)},  # 伪装成系统进程
        "tls_count": 10,
        "protocols": {"TCP": len(records)}
    }

    # 4. 正常流量 - 微软更新服务器
    records = generate_normal_traffic("20.42.73.29", start_time + timedelta(minutes=5), count=15)
    data["20.42.73.29"] = {
        "remote_ip": "20.42.73.29",
        "records": records,
        "total_packets": len(records),
        "total_bytes": sum(r["packet_size"] for r in records),
        "send_packets": sum(1 for r in records if r["direction"] == "send"),
        "recv_packets": sum(1 for r in records if r["direction"] == "recv"),
        "send_bytes": sum(r["packet_size"] for r in records if r["direction"] == "send"),
        "recv_bytes": sum(r["packet_size"] for r in records if r["direction"] == "recv"),
        "first_seen": records[0]["timestamp"],
        "last_seen": records[-1]["timestamp"],
        "remote_ports": {"443": len(records)},
        "local_ports": {r["local_port"]: 1 for r in records},
        "sni_names": {"update.microsoft.com": 10},
        "dns_names": {"update.microsoft.com": 1},
        "processes": {"svchost.exe": len(records)},
        "tls_count": len(records),
        "protocols": {"TCP": len(records)}
    }

    # 5. 可疑C2流量 - 每120秒通讯（较慢）
    records = generate_c2_traffic("91.219.236.197", start_time, period=120, count=25)
    data["91.219.236.197"] = {
        "remote_ip": "91.219.236.197",
        "records": records,
        "total_packets": len(records),
        "total_bytes": sum(r["packet_size"] for r in records),
        "send_packets": sum(1 for r in records if r["direction"] == "send"),
        "recv_packets": sum(1 for r in records if r["direction"] == "recv"),
        "send_bytes": sum(r["packet_size"] for r in records if r["direction"] == "send"),
        "recv_bytes": sum(r["packet_size"] for r in records if r["direction"] == "recv"),
        "first_seen": records[0]["timestamp"],
        "last_seen": records[-1]["timestamp"],
        "remote_ports": {"53": len(records)},  # 伪装成DNS
        "local_ports": {r["local_port"]: 1 for r in records},
        "sni_names": {},
        "dns_names": {},
        "processes": {"": len(records)},
        "tls_count": 0,
        "protocols": {"UDP": len(records)}  # 使用UDP
    }

    return data


def main():
    print("[+] 生成测试数据...")

    data = generate_test_json()

    filename = "test_capture_stats.json"
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(f"[+] 测试数据已生成: {filename}")
    print(f"[+] 共 {len(data)} 个IP")
    print("\n[+] 数据概览:")
    print("  - 142.250.185.46: 正常流量 (Google)")
    print("  - 185.220.101.42: 可疑C2流量 (每60秒)")
    print("  - 198.54.132.88: 可疑C2流量 (每45秒, 伪装)")
    print("  - 20.42.73.29: 正常流量 (Microsoft)")
    print("  - 91.219.236.197: 可疑C2流量 (每120秒)")
    print("\n[+] 运行分析:")
    print(f"    python analyzer.py {filename}")


if __name__ == '__main__':
    main()
