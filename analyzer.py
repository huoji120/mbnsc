#!/usr/bin/env python3
"""
网络流量分析工具 - C2恶意软件检测
通过分析流量的周期性特征（jitter模式）检测潜在的C2通讯
"""

import json
import argparse
import sys
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List, Tuple, Any, Optional
import math
import statistics
import requests
import time


class OTXChecker:
    """OTX威胁情报查询器"""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.enabled = api_key is not None and len(api_key) > 0
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.session = requests.Session()
        if self.enabled:
            self.session.headers.update({
                'X-OTX-API-KEY': self.api_key,
                'User-Agent': 'TrafficAnalyzer/1.0'
            })
        self.cache = {}  # 简单缓存避免重复查询

    def check_ip(self, ip: str) -> Dict[str, Any]:
        """查询IP的威胁情报"""
        if not self.enabled:
            return {'threat': False, 'pulses': []}

        cache_key = f"ip_{ip}"
        if cache_key in self.cache:
            return self.cache[cache_key]

        try:
            url = f"{self.base_url}/indicators/IPv4/{ip}/general"
            response = self.session.get(url, timeout=10)

            if response.status_code == 200:
                data = response.json()
                pulse_info = data.get('pulse_info', {})
                pulses = pulse_info.get('pulses', [])

                result = {
                    'threat': len(pulses) > 0,
                    'pulse_count': len(pulses),
                    'pulses': [
                        {
                            'name': p.get('name', ''),
                            'tags': p.get('tags', []),
                            'created': p.get('created', '')
                        }
                        for p in pulses[:3]  # 只保留前3个
                    ]
                }
                self.cache[cache_key] = result
                time.sleep(0.2)  # 避免触发API速率限制
                return result
            else:
                return {'threat': False, 'pulses': [], 'error': f'HTTP {response.status_code}'}

        except Exception as e:
            print(f"\n[-] OTX查询IP {ip} 失败: {e}")
            return {'threat': False, 'pulses': [], 'error': str(e)}

    def check_domain(self, domain: str) -> Dict[str, Any]:
        """查询域名的威胁情报"""
        if not self.enabled:
            return {'threat': False, 'pulses': []}

        cache_key = f"domain_{domain}"
        if cache_key in self.cache:
            return self.cache[cache_key]

        try:
            url = f"{self.base_url}/indicators/domain/{domain}/general"
            response = self.session.get(url, timeout=10)

            if response.status_code == 200:
                data = response.json()
                pulse_info = data.get('pulse_info', {})
                pulses = pulse_info.get('pulses', [])

                result = {
                    'threat': len(pulses) > 0,
                    'pulse_count': len(pulses),
                    'pulses': [
                        {
                            'name': p.get('name', ''),
                            'tags': p.get('tags', []),
                            'created': p.get('created', '')
                        }
                        for p in pulses[:3]  # 只保留前3个
                    ]
                }
                self.cache[cache_key] = result
                time.sleep(0.2)  # 避免触发API速率限制
                return result
            else:
                return {'threat': False, 'pulses': [], 'error': f'HTTP {response.status_code}'}

        except Exception as e:
            print(f"\n[-] OTX查询域名 {domain} 失败: {e}")
            return {'threat': False, 'pulses': [], 'error': str(e)}


class GeoIPChecker:
    """IP地理位置查询器 - 支持批量查询和代理"""

    def __init__(self, use_proxy: bool = False, proxy_host: str = None, proxy_port: int = None):
        self.base_url = "http://ip-api.com/batch"
        self.single_url = "http://ip-api.com/json/"
        self.cache = {}  # 缓存查询结果
        self.batch_size = 10  # 批量查询每次最多10个IP

        # 设置代理
        self.session = requests.Session()
        if use_proxy and proxy_host and proxy_port:
            proxies = {
                'http': f'http://{proxy_host}:{proxy_port}',
                'https': f'http://{proxy_host}:{proxy_port}'
            }
            self.session.proxies.update(proxies)
            print(f"[+] 使用代理: {proxy_host}:{proxy_port}")
        elif use_proxy:
            # 尝试使用系统代理
            self.session.trust_env = True
            print("[+] 使用系统代理设置")

    def check_ip(self, ip: str) -> Dict[str, Any]:
        """查询单个IP的地理位置信息"""
        cache_key = f"geo_{ip}"
        if cache_key in self.cache:
            return self.cache[cache_key]

        try:
            url = f"{self.single_url}{ip}?fields=status,message,country,countryCode,region,regionName,city,isp,org,as"
            response = self.session.get(url, timeout=10)

            if response.status_code == 200:
                data = response.json()

                if data.get('status') == 'success':
                    country_code = data.get('countryCode', '')
                    country = data.get('country', '')

                    # 判断是否为中国（包括大陆、香港、澳门、台湾）
                    is_china = country_code in ['CN', 'HK', 'MO', 'TW']

                    result = {
                        'success': True,
                        'country': country,
                        'country_code': country_code,
                        'region': data.get('regionName', ''),
                        'city': data.get('city', ''),
                        'isp': data.get('isp', ''),
                        'org': data.get('org', ''),
                        'as': data.get('as', ''),
                        'is_china': is_china,
                        'location_type': '国内' if is_china else '国外'
                    }
                    self.cache[cache_key] = result
                    return result
                else:
                    return {
                        'success': False,
                        'error': data.get('message', 'Unknown error'),
                        'is_china': False,
                        'location_type': '未知'
                    }
            else:
                return {
                    'success': False,
                    'error': f'HTTP {response.status_code}',
                    'is_china': False,
                    'location_type': '未知'
                }

        except Exception as e:
            print(f"\n[-] GeoIP查询IP {ip} 失败: {e}")
            return {
                'success': False,
                'error': str(e),
                'is_china': False,
                'location_type': '未知'
            }

    def check_batch_ips(self, ip_list: List[str]) -> Dict[str, Dict[str, Any]]:
        """批量查询IP的地理位置信息"""
        results = {}

        # 过滤已缓存的IP
        uncached_ips = []
        for ip in ip_list:
            cache_key = f"geo_{ip}"
            if cache_key in self.cache:
                results[ip] = self.cache[cache_key]
            else:
                uncached_ips.append(ip)

        if not uncached_ips:
            return results

        print(f"\n[+] 开始批量查询 {len(uncached_ips)} 个IP的地理位置信息...")

        # 分批处理，每批最多10个IP
        for i in range(0, len(uncached_ips), self.batch_size):
            batch_ips = uncached_ips[i:i + self.batch_size]
            batch_num = i // self.batch_size + 1
            total_batches = (len(uncached_ips) +
                             self.batch_size - 1) // self.batch_size

            print(
                f"[*] 处理批次 {batch_num}/{total_batches}: {', '.join(batch_ips)}")

            try:
                # 构建批量查询请求
                batch_data = []
                for ip in batch_ips:
                    batch_data.append({
                        "query": ip,
                        "fields": "status,message,country,countryCode,region,regionName,city,isp,org,as"
                    })

                response = self.session.post(
                    self.base_url,
                    json=batch_data,
                    headers={'Content-Type': 'application/json'},
                    timeout=30
                )

                if response.status_code == 200:
                    batch_results = response.json()

                    # 处理每个IP的结果
                    for j, ip in enumerate(batch_ips):
                        if j < len(batch_results):
                            data = batch_results[j]

                            if data.get('status') == 'success':
                                country_code = data.get('countryCode', '')
                                country = data.get('country', '')

                                # 判断是否为中国（包括大陆、香港、澳门、台湾）
                                # is_china = country_code in ['CN', 'HK', 'MO', 'TW']
                                is_china = country_code in ['CN']
                                result = {
                                    'success': True,
                                    'country': country,
                                    'country_code': country_code,
                                    'region': data.get('regionName', ''),
                                    'city': data.get('city', ''),
                                    'isp': data.get('isp', ''),
                                    'org': data.get('org', ''),
                                    'as': data.get('as', ''),
                                    'is_china': is_china,
                                    'location_type': '大陆' if is_china else '非大陆'
                                }

                                # 缓存结果
                                cache_key = f"geo_{ip}"
                                self.cache[cache_key] = result
                                results[ip] = result
                            else:
                                result = {
                                    'success': False,
                                    'error': data.get('message', 'Unknown error'),
                                    'is_china': False,
                                    'location_type': '未知'
                                }
                                self.cache[f"geo_{ip}"] = result
                                results[ip] = result
                        else:
                            # 响应数据不匹配
                            result = {
                                'success': False,
                                'error': 'Batch response mismatch',
                                'is_china': False,
                                'location_type': '未知'
                            }
                            self.cache[f"geo_{ip}"] = result
                            results[ip] = result
                else:
                    print(f"[-] 批量查询失败: HTTP {response.status_code}")
                    # 如果批量查询失败，回退到单个查询
                    for ip in batch_ips:
                        result = self.check_ip(ip)
                        results[ip] = result

                # 避免触发速率限制 - 批量查询后等待
                if batch_num < total_batches:
                    time.sleep(1.0)

            except Exception as e:
                print(f"[-] 批量查询批次 {batch_num} 失败: {e}")
                # 如果批量查询出错，回退到单个查询
                for ip in batch_ips:
                    result = self.check_ip(ip)
                    results[ip] = result

        print(f"[+] 批量查询完成，共处理 {len(results)} 个IP")
        return results


class TrafficAnalyzer:
    """流量分析器"""

    def __init__(self, json_file: str, otx_checker: Optional[OTXChecker] = None, geo_checker: Optional[GeoIPChecker] = None):
        self.json_file = json_file
        self.data: Dict[str, Any] = {}
        self.suspicious_ips: Dict[str, Dict] = {}
        self.all_results: Dict[str, Dict] = {}
        self.otx_checker = otx_checker if otx_checker else OTXChecker()
        self.geo_checker = geo_checker if geo_checker else GeoIPChecker()

    def load_data(self):
        """加载JSON数据"""
        try:
            with open(self.json_file, 'r', encoding='utf-8') as f:
                self.data = json.load(f)
            print(f"[+] 成功加载数据，共 {len(self.data)} 个远程IP")
        except FileNotFoundError:
            print(f"[-] 错误: 文件 {self.json_file} 不存在")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"[-] 错误: JSON解析失败 - {e}")
            sys.exit(1)

    def parse_timestamp(self, ts_str: str) -> datetime:
        """解析时间戳字符串"""
        # Go的时间格式: 2006-01-02T15:04:05.999999999Z07:00
        # 尝试多种格式
        formats = [
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S%z"
        ]

        for fmt in formats:
            try:
                return datetime.strptime(ts_str, fmt)
            except ValueError:
                continue

        # 如果都失败，尝试截断纳秒部分
        try:
            # 移除纳秒精度（保留6位微秒）
            if '.' in ts_str:
                parts = ts_str.split('.')
                microsec = parts[1][:6]  # 只保留6位
                rest = parts[1][6:]
                # 找到时区部分
                tz_part = ""
                for i, c in enumerate(rest):
                    if c in ['+', '-', 'Z']:
                        tz_part = rest[i:]
                        break
                ts_str = f"{parts[0]}.{microsec}{tz_part}"
            return datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S.%f%z")
        except Exception as e:
            print(f"[-] 警告: 无法解析时间戳 {ts_str}: {e}")
            return datetime.now()

    def calculate_intervals(self, records: List[Dict]) -> List[float]:
        """计算数据包之间的时间间隔（秒）"""
        if len(records) < 2:
            return []

        intervals = []
        timestamps = [self.parse_timestamp(r['timestamp']) for r in records]

        for i in range(1, len(timestamps)):
            delta = (timestamps[i] - timestamps[i-1]).total_seconds()
            if delta > 0:  # 忽略负值或零
                intervals.append(delta)

        return intervals

    def detect_periodic_pattern(self, intervals: List[float], tolerance: float = 0.3) -> Tuple[bool, float, float]:
        """
        检测周期性模式

        返回: (是否周期性, 周期时间(秒), 标准差)

        tolerance: 容差系数，默认30%（0.3）
        """
        if len(intervals) < 5:  # 至少需要5个间隔才能判断
            return False, 0, 0

        # 计算平均间隔和标准差
        mean_interval = statistics.mean(intervals)
        if mean_interval < 1:  # 间隔太短（<1秒），不太可能是C2
            return False, 0, 0

        stdev = statistics.stdev(intervals) if len(intervals) > 1 else 0

        # 计算变异系数 (CV = 标准差/平均值)
        cv = stdev / mean_interval if mean_interval > 0 else float('inf')

        # 如果变异系数小于容差，认为是周期性的
        is_periodic = cv < tolerance

        # 额外检查：至少50%的间隔应该在 mean ± (tolerance * mean) 范围内
        in_range_count = sum(1 for i in intervals
                             if abs(i - mean_interval) <= tolerance * mean_interval)
        in_range_ratio = in_range_count / len(intervals)

        is_periodic = is_periodic and in_range_ratio >= 0.5

        return is_periodic, mean_interval, cv

    def classify_traffic_pattern(self, records: List[Dict]) -> Dict:
        """
        根据send/recv模式对流量进行分类

        返回: {
            'pattern': str,  # 流量模式类型
            'description': str,  # 模式描述
            'confidence': float  # 置信度 0-1
        }
        """
        if not records:
            return {'pattern': 'unknown', 'description': '无数据', 'confidence': 0.0}

        # 统计send和recv
        send_count = sum(1 for r in records if r['direction'] == 'send')
        recv_count = sum(1 for r in records if r['direction'] == 'recv')
        total_count = len(records)

        send_bytes = sum(r['packet_size']
                         for r in records if r['direction'] == 'send')
        recv_bytes = sum(r['packet_size']
                         for r in records if r['direction'] == 'recv')

        avg_send_size = send_bytes / send_count if send_count > 0 else 0
        avg_recv_size = recv_bytes / recv_count if recv_count > 0 else 0

        # 计算时间间隔信息（用于某些模式检测）
        intervals = self.calculate_intervals(records)
        avg_interval = statistics.mean(intervals) if intervals else 0
        interval_stdev = statistics.stdev(intervals) if len(intervals) > 1 else 0

        # 计算包大小的标准差（用于检测一致性）
        send_sizes = [r['packet_size'] for r in records if r['direction'] == 'send']
        recv_sizes = [r['packet_size'] for r in records if r['direction'] == 'recv']
        send_size_stdev = statistics.stdev(send_sizes) if len(send_sizes) > 1 else 0
        recv_size_stdev = statistics.stdev(recv_sizes) if len(recv_sizes) > 1 else 0

        # 分析send/recv交替模式
        directions = [r['direction'] for r in records]

        # 统计连续相同方向的最大长度
        max_consecutive_send = 0
        max_consecutive_recv = 0
        current_consecutive = 1

        for i in range(1, len(directions)):
            if directions[i] == directions[i-1]:
                current_consecutive += 1
            else:
                if directions[i-1] == 'send':
                    max_consecutive_send = max(
                        max_consecutive_send, current_consecutive)
                else:
                    max_consecutive_recv = max(
                        max_consecutive_recv, current_consecutive)
                current_consecutive = 1

        # 处理最后一段
        if directions:
            if directions[-1] == 'send':
                max_consecutive_send = max(
                    max_consecutive_send, current_consecutive)
            else:
                max_consecutive_recv = max(
                    max_consecutive_recv, current_consecutive)

        # 计算交替比例（send后跟recv的次数）
        alternating_count = 0
        for i in range(len(directions) - 1):
            if directions[i] != directions[i+1]:
                alternating_count += 1
        alternating_ratio = alternating_count / \
            (len(directions) - 1) if len(directions) > 1 else 0

        # 按顺序检查各种模式（优先级从高到低）

        # 1. 被阻断（只有send，没有recv）
        if recv_count == 0 and send_count > 0:
            return {
                'pattern': 'blocked',
                'description': f'被阻断 (仅发送 {send_count} 次，无响应)',
                'confidence': 0.95
            }

        # 2. 单向接收（只有recv，没有send）- 可能是推送通知或广播
        if send_count == 0 and recv_count > 0:
            return {
                'pattern': 'recv_only',
                'description': f'单向接收 (仅接收 {recv_count} 次)',
                'confidence': 0.90
            }

        # 3. 心跳模式（send和recv交替，包大小都很小）
        # 特征：高度交替，包都很小（<500字节），send和recv数量接近
        if (alternating_ratio > 0.7 and
            abs(send_count - recv_count) <= max(3, total_count * 0.2) and
                avg_send_size < 500 and avg_recv_size < 500):
            return {
                'pattern': 'heartbeat',
                'description': f'心跳 (send {send_count} ↔ recv {recv_count}, 平均 {avg_send_size:.0f}↕{avg_recv_size:.0f}B)',
                'confidence': 0.85
            }

        # 4. 下载模式（send少recv多，recv字节数远大于send）
        # 特征：recv次数远多于send，recv字节数远大于send
        if (recv_count > send_count * 2 and
            recv_bytes > send_bytes * 5 and
                send_count > 0):
            return {
                'pattern': 'download',
                'description': f'下载 (send {send_count}次 → recv {recv_count}次, {self._format_bytes(recv_bytes)})',
                'confidence': 0.88
            }

        # 5. 上传模式（send多recv少，send字节数远大于recv）
        if (send_count > recv_count * 2 and
            send_bytes > recv_bytes * 5 and
                recv_count > 0):
            return {
                'pattern': 'upload',
                'description': f'上传 (send {send_count}次 → recv {recv_count}次, {self._format_bytes(send_bytes)})',
                'confidence': 0.88
            }

        # 6. 交互式通信（send和recv频繁交替，数量接近）
        if (alternating_ratio > 0.5 and
                abs(send_count - recv_count) <= max(5, total_count * 0.3)):
            return {
                'pattern': 'interactive',
                'description': f'交互式 (send {send_count} ↔ recv {recv_count}, 交替率 {alternating_ratio:.0%})',
                'confidence': 0.75
            }

        # 7. 批量传输（大量连续的send或recv）
        if max_consecutive_send > 10 or max_consecutive_recv > 10:
            if max_consecutive_recv > max_consecutive_send:
                return {
                    'pattern': 'bulk_transfer',
                    'description': f'批量接收 (连续recv {max_consecutive_recv}次)',
                    'confidence': 0.80
                }
            else:
                return {
                    'pattern': 'bulk_transfer',
                    'description': f'批量发送 (连续send {max_consecutive_send}次)',
                    'confidence': 0.80
                }

        # 8. 请求-响应模式（少量交互，不符合其他特征）
        if total_count <= 10 and send_count > 0 and recv_count > 0:
            return {
                'pattern': 'request_response',
                'description': f'请求-响应 (send {send_count}, recv {recv_count})',
                'confidence': 0.70
            }

        # 9. 扫描/探测（少量小包，响应极少）
        if (total_count <= 15 and
            send_count > recv_count * 3 and
                avg_send_size < 200):
            return {
                'pattern': 'scan_probe',
                'description': f'扫描探测 (send {send_count}次小包, recv仅{recv_count}次)',
                'confidence': 0.75
            }

        # 10. 信标通讯（Beaconing）- 严格周期性，包大小一致（C2特征）
        if (len(intervals) >= 5 and avg_interval >= 5 and
            interval_stdev > 0 and (interval_stdev / avg_interval) < 0.15 and
            send_count > 0 and recv_count > 0 and
            avg_send_size < 2000 and avg_recv_size < 2000 and
                send_size_stdev < avg_send_size * 0.3):
            return {
                'pattern': 'beaconing',
                'description': f'信标通讯 (周期 {avg_interval:.1f}s, send {send_count}↔recv {recv_count}, 平均 {avg_send_size:.0f}B)',
                'confidence': 0.92
            }

        # 11. 数据泄露（Data Exfiltration）- 持续大量上传
        if (send_count > 10 and
            send_bytes > recv_bytes * 10 and
            avg_send_size > 1024 and
                send_count > recv_count * 1.5):
            return {
                'pattern': 'data_exfiltration',
                'description': f'疑似数据泄露 (上传 {self._format_bytes(send_bytes)}, {send_count}次发送)',
                'confidence': 0.85
            }

        # 12. 慢速滴漏（Slow Drip）- 长时间间隔的低频通信
        if (len(intervals) >= 3 and
            avg_interval > 300 and  # 超过5分钟间隔
            total_count >= 3 and total_count <= 30 and
                (send_count > 0 or recv_count > 0)):
            return {
                'pattern': 'slow_drip',
                'description': f'慢速通讯 (平均间隔 {avg_interval/60:.1f}分钟, {total_count}个包)',
                'confidence': 0.78
            }

        # 13. 突发活动（Burst Activity）- 间隔差异大，有明显沉默期
        if (len(intervals) >= 5 and
            interval_stdev > 0 and
            (interval_stdev / avg_interval) > 1.5 and  # 高变异性
            max(intervals) > avg_interval * 5 and
                total_count >= 10):
            return {
                'pattern': 'burst_activity',
                'description': f'突发活动 (间隔不规律, {total_count}个包, 最大间隔 {max(intervals):.1f}s)',
                'confidence': 0.72
            }

        # 14. 非对称交互（Asymmetric Interactive）- 交互式但包大小差异大
        if (alternating_ratio > 0.4 and
            send_count > 0 and recv_count > 0 and
            abs(send_count - recv_count) <= max(5, total_count * 0.4) and
            ((avg_send_size > avg_recv_size * 5) or (avg_recv_size > avg_send_size * 5)) and
                total_count >= 10):
            if avg_send_size > avg_recv_size:
                return {
                    'pattern': 'asymmetric_interactive',
                    'description': f'非对称交互 (send {avg_send_size:.0f}B >> recv {avg_recv_size:.0f}B, {total_count}次交互)',
                    'confidence': 0.80
                }
            else:
                return {
                    'pattern': 'asymmetric_interactive',
                    'description': f'非对称交互 (recv {avg_recv_size:.0f}B >> send {avg_send_size:.0f}B, {total_count}次交互)',
                    'confidence': 0.80
                }

        # 15. 连接测试（Connection Test）- 极少数据包
        if total_count <= 3 and (send_count > 0 or recv_count > 0):
            return {
                'pattern': 'connection_test',
                'description': f'连接测试 (仅 {total_count}个包)',
                'confidence': 0.68
            }

        # 16. 大文件传输（Large Transfer）- 少量超大包
        if (total_count <= 20 and
            ((avg_send_size > 10240) or (avg_recv_size > 10240)) and
                (send_bytes + recv_bytes) > 51200):  # 总共超过50KB
            if send_bytes > recv_bytes:
                return {
                    'pattern': 'large_transfer',
                    'description': f'大文件上传 ({self._format_bytes(send_bytes)}, {send_count}个大包)',
                    'confidence': 0.83
                }
            else:
                return {
                    'pattern': 'large_transfer',
                    'description': f'大文件下载 ({self._format_bytes(recv_bytes)}, {recv_count}个大包)',
                    'confidence': 0.83
                }

        # 17. 保活通讯（Keep Alive）- 定期极小包
        if (len(intervals) >= 3 and
            avg_interval >= 30 and  # 至少30秒间隔
            avg_interval <= 600 and  # 不超过10分钟
            interval_stdev > 0 and (interval_stdev / avg_interval) < 0.4 and
            avg_send_size < 200 and avg_recv_size < 200 and
                total_count >= 3 and total_count <= 50):
            return {
                'pattern': 'keep_alive',
                'description': f'保活通讯 (周期 {avg_interval:.0f}s, 小包 {avg_send_size:.0f}B)',
                'confidence': 0.76
            }

        # 18. 默认：混合模式
        return {
            'pattern': 'mixed',
            'description': f'混合模式 (send {send_count}, recv {recv_count})',
            'confidence': 0.50
        }

    def analyze_ip(self, ip: str, ip_stats: Dict) -> Dict:
        """分析单个IP的流量模式"""
        records = ip_stats.get('records', [])

        if len(records) < 5:  # 数据包太少，跳过
            return None

        # 计算时间间隔
        intervals = self.calculate_intervals(records)

        if not intervals:
            return None

        # 检测周期性
        is_periodic, period, cv = self.detect_periodic_pattern(intervals)

        # 识别流量模式
        traffic_pattern = self.classify_traffic_pattern(records)

        # 提取时间序列数据（用于绘图）
        timeline = []
        for record in records:
            ts = self.parse_timestamp(record['timestamp'])
            timeline.append({
                'timestamp': ts.strftime("%Y-%m-%d %H:%M:%S"),  # 秒级精度
                'timestamp_unix': int(ts.timestamp()),  # Unix时间戳（秒）
                'packet_size': record['packet_size'],
                'direction': record['direction']
            })

        # 按时间排序
        timeline.sort(key=lambda x: x['timestamp_unix'])

        # 提取其他信息
        sni_list = list(ip_stats.get('sni_names', {}).keys())
        dns_list = list(ip_stats.get('dns_names', {}).keys())
        processes = list(ip_stats.get('processes', {}).keys())

        # IOC查询
        ioc_data = {
            'ip_threat': False,
            'ip_pulses': [],
            'sni_threats': {},
            'dns_threats': {}
        }

        if self.otx_checker.enabled:
            # 查询IP
            ip_result = self.otx_checker.check_ip(ip)
            ioc_data['ip_threat'] = ip_result.get('threat', False)
            ioc_data['ip_pulses'] = ip_result.get('pulses', [])

            # 查询SNI域名
            for sni in sni_list:
                sni_result = self.otx_checker.check_domain(sni)
                if sni_result.get('threat', False):
                    ioc_data['sni_threats'][sni] = sni_result

            # 查询DNS域名
            for dns in dns_list:
                dns_result = self.otx_checker.check_domain(dns)
                if dns_result.get('threat', False):
                    ioc_data['dns_threats'][dns] = dns_result

        # GeoIP查询 - 现在由analyze_all方法批量处理
        # 这里保留兜底逻辑，以防某个IP没有被批量查询到
        geo_data = self.geo_checker.check_ip(ip)

        analysis_result = {
            'ip': ip,
            'is_suspicious': is_periodic,
            'period': period,
            'cv': cv,
            'packet_count': len(records),
            'timeline': timeline,
            'sni_names': sni_list,
            'dns_names': dns_list,
            'processes': processes,
            'total_bytes': ip_stats.get('total_bytes', 0),
            'first_seen': ip_stats.get('first_seen', ''),
            'last_seen': ip_stats.get('last_seen', ''),
            'protocols': ip_stats.get('protocols', {}),
            'remote_ports': ip_stats.get('remote_ports', {}),
            'ioc': ioc_data,  # 添加IOC数据
            'traffic_pattern': traffic_pattern,  # 添加流量模式标签
            'geo': geo_data  # 添加地理位置数据
        }

        return analysis_result

    def analyze_all(self):
        """分析所有IP"""
        print("\n[+] 开始分析流量模式...")

        total = len(self.data)
        suspicious_count = 0
        self.all_results = {}  # 存储所有IP的分析结果

        # 先收集所有IP，准备批量查询地理位置
        all_ips = list(self.data.keys())
        print(f"\n[+] 批量查询 {len(all_ips)} 个IP的地理位置信息...")
        geo_results = self.geo_checker.check_batch_ips(all_ips)

        for idx, (ip, ip_stats) in enumerate(self.data.items(), 1):
            print(f"\r[*] 进度: {idx}/{total} - 分析 {ip}", end='', flush=True)

            result = self.analyze_ip(ip, ip_stats)
            if result:
                # 使用预先查询的地理位置信息
                if ip in geo_results:
                    result['geo'] = geo_results[ip]

                self.all_results[ip] = result
                if result['is_suspicious']:
                    self.suspicious_ips[ip] = result
                    suspicious_count += 1

        print(f"\n[+] 分析完成！")
        print(f"[+] 共 {len(self.all_results)} 个IP")
        print(f"[+] 其中 {suspicious_count} 个检测到周期性通讯模式")

    def generate_html_report(self, output_file: str = "traffic_report.html"):
        """生成HTML报表"""
        print(f"\n[+] 生成HTML报表: {output_file}")

        # 按数据包数量排序（流量最多的在前）
        sorted_ips = sorted(self.all_results.items(),
                            key=lambda x: x[1]['packet_count'], reverse=True)

        html = self._generate_html_header()

        # 添加概览
        html += self._generate_summary(sorted_ips)

        # 为每个IP生成详细报告
        for ip, analysis in sorted_ips:
            html += self._generate_ip_section(ip, analysis)

        # 添加汇总表格
        html += self._generate_summary_table(sorted_ips)

        html += self._generate_html_footer()

        # 写入文件
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)

        print(f"[+] 报表已生成: {output_file}")

    def _generate_html_header(self) -> str:
        """生成HTML头部"""
        return '''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>网络流量分析报告 - C2恶意软件检测</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chartjs-adapter-date-fns@3.0.0/dist/chartjs-adapter-date-fns.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/hammerjs@2.0.8/hammer.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chartjs-plugin-zoom@2.0.1/dist/chartjs-plugin-zoom.min.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
            padding: 40px;
        }

        h1 {
            color: #2d3748;
            margin-bottom: 10px;
            font-size: 32px;
            border-bottom: 3px solid #667eea;
            padding-bottom: 15px;
        }

        h2 {
            color: #4a5568;
            margin-top: 40px;
            margin-bottom: 20px;
            font-size: 24px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .alert-icon {
            color: #e53e3e;
            font-size: 28px;
        }

        .summary {
            background: linear-gradient(135deg, #f6ad55 0%, #ed8936 100%);
            color: white;
            padding: 25px;
            border-radius: 8px;
            margin: 20px 0;
        }

        .summary h3 {
            margin-bottom: 15px;
            font-size: 20px;
        }

        .summary-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }

        .stat-box {
            background: rgba(255,255,255,0.2);
            padding: 15px;
            border-radius: 6px;
            backdrop-filter: blur(10px);
        }

        .stat-label {
            font-size: 14px;
            opacity: 0.9;
            margin-bottom: 5px;
        }

        .stat-value {
            font-size: 28px;
            font-weight: bold;
        }

        .ip-section {
            background: #f7fafc;
            border-left: 5px solid #e53e3e;
            padding: 25px;
            margin: 30px 0;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
        }

        .ip-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            flex-wrap: wrap;
            gap: 15px;
        }

        .ip-title {
            font-size: 22px;
            font-weight: bold;
            color: #2d3748;
        }

        .warning-badge {
            background: #fed7d7;
            color: #c53030;
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 14px;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }

        .info-badge {
            background: #bee3f8;
            color: #2c5282;
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 14px;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }

        .normal-info {
            background: #e6fffa;
            border: 2px solid #81e6d9;
            padding: 15px;
            border-radius: 8px;
            margin: 15px 0;
            color: #234e52;
        }

        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }

        .info-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .info-card h4 {
            color: #4a5568;
            margin-bottom: 12px;
            font-size: 16px;
            border-bottom: 2px solid #e2e8f0;
            padding-bottom: 8px;
        }

        .info-card ul {
            list-style: none;
        }

        .info-card li {
            padding: 6px 0;
            color: #2d3748;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .info-card li:before {
            content: "▸";
            color: #667eea;
            font-weight: bold;
        }

        .chart-container {
            background: white;
            padding: 25px;
            border-radius: 8px;
            margin: 20px 0;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            height: 450px;
        }

        .metric {
            display: inline-block;
            background: #e6fffa;
            color: #234e52;
            padding: 6px 12px;
            border-radius: 6px;
            margin: 5px;
            font-size: 14px;
            font-weight: 600;
        }

        .period-info {
            background: #fff5f5;
            border: 2px solid #fc8181;
            padding: 15px;
            border-radius: 8px;
            margin: 15px 0;
        }

        .period-info strong {
            color: #c53030;
            font-size: 18px;
        }

        .footer {
            margin-top: 50px;
            padding-top: 20px;
            border-top: 2px solid #e2e8f0;
            text-align: center;
            color: #718096;
            font-size: 14px;
        }

        .no-data {
            color: #a0aec0;
            font-style: italic;
        }

        .summary-table-section {
            margin-top: 60px;
            margin-bottom: 40px;
        }

        .summary-table-section h2 {
            color: #2d3748;
            margin-bottom: 20px;
            font-size: 28px;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
        }

        .ip-dns-table {
            width: 100%;
            border-collapse: collapse;
            background: white;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }

        .ip-dns-table thead {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }

        .ip-dns-table thead th {
            padding: 15px;
            text-align: left;
            font-weight: 600;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .ip-dns-table tbody tr {
            border-bottom: 1px solid #e2e8f0;
            transition: background-color 0.2s;
        }

        .ip-dns-table tbody tr:hover {
            background-color: #f7fafc;
        }

        .ip-dns-table tbody tr:last-child {
            border-bottom: none;
        }

        .ip-dns-table tbody td {
            padding: 12px 15px;
            color: #2d3748;
        }

        .ip-column {
            font-family: 'Courier New', monospace;
            font-weight: 600;
            color: #4299e1;
            white-space: nowrap;
        }

        .domain-list {
            line-height: 1.6;
        }

        .domain-item {
            display: inline-block;
            background: #e6fffa;
            color: #234e52;
            padding: 4px 10px;
            margin: 2px;
            border-radius: 4px;
            font-size: 13px;
        }

        .no-domain {
            color: #a0aec0;
            font-style: italic;
        }

        .periodic-indicator {
            display: inline-block;
            background: #fed7d7;
            color: #c53030;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: bold;
            margin-left: 8px;
        }

        @media (max-width: 768px) {
            .container {
                padding: 20px;
            }

            h1 {
                font-size: 24px;
            }

            .chart-container {
                height: 300px;
            }

            .ip-dns-table {
                font-size: 12px;
            }

            .ip-dns-table thead th,
            .ip-dns-table tbody td {
                padding: 10px 8px;
            }

            .domain-item {
                font-size: 11px;
                padding: 3px 6px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 网络流量分析报告 - C2恶意软件检测</h1>
        <p style="color: #718096; margin: 15px 0;">生成时间: ''' + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + '''</p>
'''

    def _generate_summary(self, sorted_ips: List) -> str:
        """生成概览部分"""
        total_ips = len(sorted_ips)
        suspicious_count = sum(
            1 for _, analysis in sorted_ips if analysis['is_suspicious'])
        ioc_count = sum(1 for _, analysis in sorted_ips
                        if analysis.get('ioc', {}).get('ip_threat', False) or
                        analysis.get('ioc', {}).get('sni_threats', {}) or
                        analysis.get('ioc', {}).get('dns_threats', {}))

        # 统计国内/国外IP数量
        china_count = sum(1 for _, analysis in sorted_ips if analysis.get(
            'geo', {}).get('is_china', False))
        foreign_count = sum(1 for _, analysis in sorted_ips if not analysis.get(
            'geo', {}).get('is_china', False) and analysis.get('geo', {}).get('success', False))
        unknown_geo_count = sum(1 for _, analysis in sorted_ips if not analysis.get(
            'geo', {}).get('success', False))

        # 统计各种流量模式的数量
        pattern_counts = {}
        for _, analysis in sorted_ips:
            pattern_type = analysis.get(
                'traffic_pattern', {}).get('pattern', 'unknown')
            pattern_counts[pattern_type] = pattern_counts.get(
                pattern_type, 0) + 1

        # 流量模式统计HTML
        pattern_stats_html = ''
        if pattern_counts:
            pattern_names_cn = {
                'heartbeat': '心跳',
                'download': '下载',
                'upload': '上传',
                'blocked': '被阻断',
                'recv_only': '单向接收',
                'interactive': '交互式',
                'bulk_transfer': '批量传输',
                'request_response': '请求-响应',
                'scan_probe': '扫描探测',
                'beaconing': '信标通讯',
                'data_exfiltration': '数据泄露',
                'slow_drip': '慢速滴漏',
                'burst_activity': '突发活动',
                'asymmetric_interactive': '非对称交互',
                'connection_test': '连接测试',
                'large_transfer': '大文件传输',
                'keep_alive': '保活通讯',
                'mixed': '混合模式',
                'unknown': '未知'
            }

            pattern_items = []
            for pattern_type, count in sorted(pattern_counts.items(), key=lambda x: x[1], reverse=True):
                pattern_name = pattern_names_cn.get(pattern_type, pattern_type)
                pattern_items.append(f'{pattern_name}: {count}')

            pattern_stats_html = f'''
            <div style="background: #e6fffa; border-left: 4px solid #319795; padding: 15px; border-radius: 8px; margin: 15px 0;">
                <h4 style="color: #234e52; margin-bottom: 8px;">📊 流量模式分布</h4>
                <p style="color: #234e52; line-height: 1.6; margin: 0;">
                    {' | '.join(pattern_items)}
                </p>
            </div>
            '''

        html = f'''
        <div class="summary">
            <h3>📊 流量分析概览</h3>
            <div class="summary-stats">
                <div class="stat-box">
                    <div class="stat-label">分析IP总数</div>
                    <div class="stat-value">{total_ips}</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">检测到周期性通讯</div>
                    <div class="stat-value">{suspicious_count}</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">周期性比例</div>
                    <div class="stat-value">{(suspicious_count/total_ips*100) if total_ips else 0:.1f}%</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">🛡️ OTX IOC匹配</div>
                    <div class="stat-value">{ioc_count}</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">🇨🇳 国内IP</div>
                    <div class="stat-value">{china_count}</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">🌍 国外IP</div>
                    <div class="stat-value">{foreign_count}</div>
                </div>
            </div>
        </div>

        {pattern_stats_html}

        <div style="background: #e6fffa; border-left: 4px solid #319795; padding: 20px; border-radius: 8px; margin: 20px 0;">
            <h4 style="color: #234e52; margin-bottom: 10px;">ℹ️ 报表说明</h4>
            <p style="color: #234e52; line-height: 1.6;">
                本报表展示<strong>所有IP的流量时间序列图</strong>，帮助你分析网络通讯模式。<br>
                图表按<strong>数据包数量</strong>排序，流量最多的IP显示在前面。<br>
                标记为"周期性通讯"的IP具有规律的时间间隔特征（如C2心跳、定时同步等）。<br>
                <strong>流量模式标签</strong>根据send/recv行为自动识别，包括：心跳、下载、上传、被阻断等多种类型。<br>
                🛡️ <strong>IOC标记</strong>基于AlienVault OTX威胁情报库，匹配到威胁情报的IP/域名会特别标注。
            </p>
        </div>
        '''

        return html

    def _generate_ip_section(self, ip: str, analysis: Dict) -> str:
        """为单个IP生成详细分析部分"""
        chart_id = f"chart_{ip.replace('.', '_').replace(':', '_')}"

        # 准备图表数据 - 使用Unix时间戳确保正确排序
        # 所有数据点（包含发送和接收）
        all_points = []

        for point in analysis['timeline']:
            all_points.append({
                'x': point['timestamp_unix'] * 1000,  # Chart.js需要毫秒级时间戳
                'y': point['packet_size'],
                'direction': point['direction'],
                'time_label': point['timestamp']  # 用于tooltip显示
            })

        # 分离发送和接收数据（保持时间戳）
        send_points = [{'x': p['x'], 'y': p['y']}
                       for p in all_points if p['direction'] == 'send']
        recv_points = [{'x': p['x'], 'y': p['y']}
                       for p in all_points if p['direction'] == 'recv']

        # DNS和SNI信息
        ioc_data = analysis.get('ioc', {})

        # 生成DNS HTML（带IOC标记）
        if analysis['dns_names']:
            dns_items = []
            for dns in analysis['dns_names']:
                if dns in ioc_data.get('dns_threats', {}):
                    dns_items.append(
                        f'<span style="background: #fed7d7; color: #c53030; padding: 3px 8px; border-radius: 4px; font-weight: bold;">🚨 {dns}</span>')
                else:
                    dns_items.append(dns)
            dns_html = ', '.join(dns_items)
        else:
            dns_html = '<span class="no-data">无DNS记录</span>'

        # 生成SNI HTML（带IOC标记）
        if analysis['sni_names']:
            sni_items = []
            for sni in analysis['sni_names']:
                if sni in ioc_data.get('sni_threats', {}):
                    sni_items.append(
                        f'<span style="background: #fed7d7; color: #c53030; padding: 3px 8px; border-radius: 4px; font-weight: bold;">🚨 {sni}</span>')
                else:
                    sni_items.append(sni)
            sni_html = ', '.join(sni_items)
        else:
            sni_html = '<span class="no-data">无SNI记录</span>'

        processes_html = ', '.join(
            analysis['processes']) if analysis['processes'] else '<span class="no-data">未知</span>'

        # 协议和端口信息
        protocols_html = ', '.join([f"{k}({v})" for k, v in analysis['protocols'].items(
        )]) if analysis['protocols'] else '无'
        ports_html = ', '.join([f"{k}({v})" for k, v in analysis['remote_ports'].items(
        )]) if analysis['remote_ports'] else '无'

        # IOC信息卡片
        ioc_card_html = ''
        if ioc_data.get('ip_threat', False) or ioc_data.get('sni_threats') or ioc_data.get('dns_threats'):
            ioc_details = []

            if ioc_data.get('ip_threat', False):
                pulses = ioc_data.get('ip_pulses', [])
                ioc_details.append(f'<li>IP在威胁情报库中: {len(pulses)} 个情报脉冲</li>')
                for pulse in pulses[:2]:  # 显示前2个
                    pulse_name = pulse.get('name', '未知')
                    tags = ', '.join(pulse.get('tags', [])[:5])
                    ioc_details.append(
                        f'<li style="margin-left: 20px; font-size: 12px;">• {pulse_name} ({tags})</li>')

            if ioc_data.get('sni_threats'):
                ioc_details.append(
                    f'<li>SNI域名威胁: {len(ioc_data["sni_threats"])} 个匹配</li>')

            if ioc_data.get('dns_threats'):
                ioc_details.append(
                    f'<li>DNS域名威胁: {len(ioc_data["dns_threats"])} 个匹配</li>')

            ioc_card_html = f'''
                <div class="info-card" style="background: #fff5f5; border: 2px solid #fc8181;">
                    <h4 style="color: #c53030;">🚨 OTX威胁情报匹配</h4>
                    <ul style="color: #742a2a;">
                        {"".join(ioc_details)}
                    </ul>
                </div>
            '''

        # 获取流量模式信息
        traffic_pattern = analysis.get('traffic_pattern', {})
        pattern_type = traffic_pattern.get('pattern', 'unknown')
        pattern_desc = traffic_pattern.get('description', '未知')
        pattern_confidence = traffic_pattern.get('confidence', 0.0)

        # 流量模式的颜色映射
        pattern_colors = {
            'heartbeat': '#f6ad55',  # 橙色
            'download': '#48bb78',   # 绿色
            'upload': '#4299e1',     # 蓝色
            'blocked': '#e53e3e',    # 红色
            'recv_only': '#9f7aea',  # 紫色
            'interactive': '#38b2ac',  # 青色
            'bulk_transfer': '#ed8936',  # 深橙
            'request_response': '#667eea',  # 靛蓝
            'scan_probe': '#fc8181',  # 粉红
            'beaconing': '#c53030',   # 深红（高危）
            'data_exfiltration': '#dd6b20',  # 深橙红（高危）
            'slow_drip': '#805ad5',   # 深紫
            'burst_activity': '#d69e2e',  # 金黄
            'asymmetric_interactive': '#3182ce',  # 深蓝
            'connection_test': '#718096',  # 中灰
            'large_transfer': '#2c7a7b',  # 深青
            'keep_alive': '#68d391',  # 浅绿
            'mixed': '#a0aec0',      # 灰色
            'unknown': '#cbd5e0'     # 浅灰
        }

        pattern_icons = {
            'heartbeat': '💓',
            'download': '⬇️',
            'upload': '⬆️',
            'blocked': '🚫',
            'recv_only': '📥',
            'interactive': '💬',
            'bulk_transfer': '📦',
            'request_response': '🔄',
            'scan_probe': '🔍',
            'beaconing': '🚨',        # 警报（高危）
            'data_exfiltration': '⚠️',  # 警告（高危）
            'slow_drip': '💧',        # 水滴
            'burst_activity': '💥',    # 爆炸
            'asymmetric_interactive': '⚖️',  # 天平
            'connection_test': '🔌',   # 插头
            'large_transfer': '📤',    # 文件传输
            'keep_alive': '🔗',       # 链接
            'mixed': '🔀',
            'unknown': '❓'
        }

        pattern_color = pattern_colors.get(pattern_type, '#cbd5e0')
        pattern_icon = pattern_icons.get(pattern_type, '❓')

        # 生成流量模式标签HTML
        pattern_badge_html = f'''
        <div class="info-badge" style="background: {pattern_color}; color: white;">
            {pattern_icon} 流量模式: {pattern_desc}
        </div>
        '''

        # 生成地理位置标签HTML
        geo_data = analysis.get('geo', {})
        if geo_data.get('success', False):
            is_china = geo_data.get('is_china', False)
            country = geo_data.get('country', '未知')
            location_type = geo_data.get('location_type', '未知')

            if is_china:
                geo_color = '#48bb78'  # 绿色表示国内
                geo_icon = '🇨🇳'
            else:
                geo_color = '#ed8936'  # 橙色表示国外
                geo_icon = '🌍'

            geo_badge_html = f'''
            <div class="info-badge" style="background: {geo_color}; color: white;">
                {geo_icon} {location_type}: {country}
            </div>
            '''
        else:
            geo_badge_html = '''
            <div class="info-badge" style="background: #a0aec0; color: white;">
                ❓ 位置: 未知
            </div>
            '''

        # 根据是否周期性使用不同的样式
        if analysis['is_suspicious']:
            border_color = '#e53e3e'  # 红色
            badge_html = '<div class="warning-badge">⚠️ 检测到周期性通讯</div>'
            period_info_html = f'''
            <div class="period-info">
                <strong>周期性特征:</strong>
                约每 <strong>{analysis['period']:.2f} 秒</strong> 通讯一次
                (变异系数: {analysis['cv']:.3f}, 越小越规律)
            </div>
            '''
        else:
            border_color = '#4299e1'  # 蓝色
            badge_html = '<div class="info-badge">📊 正常流量</div>'
            if analysis['period'] > 0:
                period_info_html = f'''
                <div class="normal-info">
                    <strong>通讯特征:</strong>
                    平均间隔 <strong>{analysis['period']:.2f} 秒</strong>
                    (变异系数: {analysis['cv']:.3f})
                </div>
                '''
            else:
                period_info_html = ''

        # 如果有IOC威胁，使用红色边框
        if ioc_data.get('ip_threat', False):
            border_color = '#c53030'

        html = f'''
        <div class="ip-section" style="border-left-color: {border_color};">
            <div class="ip-header">
                <div class="ip-title">🎯 {ip}</div>
                <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                    {badge_html}
                    {pattern_badge_html}
                    {geo_badge_html}
                </div>
            </div>

            {period_info_html}

            <div class="info-grid">
                <div class="info-card">
                    <h4>🔗 关联域名 (DNS)</h4>
                    <p>{dns_html}</p>
                </div>

                <div class="info-card">
                    <h4>🔐 TLS SNI</h4>
                    <p>{sni_html}</p>
                </div>

                <div class="info-card">
                    <h4>⚙️ 关联进程</h4>
                    <p>{processes_html}</p>
                </div>

                <div class="info-card">
                    <h4>📊 基本统计</h4>
                    <ul>
                        <li>数据包数: {analysis['packet_count']}</li>
                        <li>总流量: {self._format_bytes(analysis['total_bytes'])}</li>
                        <li>协议: {protocols_html}</li>
                        <li>远程端口: {ports_html}</li>
                    </ul>
                </div>

                <div class="info-card">
                    <h4>🌍 地理位置</h4>
                    <ul>
                        <li>位置: {geo_data.get('location_type', '未知')}</li>
                        <li>国家: {geo_data.get('country', '未知')}</li>
                        <li>地区: {geo_data.get('region', '未知') if geo_data.get('region') else '未知'}</li>
                        <li>ISP: {geo_data.get('isp', '未知') if geo_data.get('isp') else '未知'}</li>
                    </ul>
                </div>

                {ioc_card_html}
            </div>

            <h3 style="margin: 30px 0 15px 0; color: #2d3748;">📈 流量时间序列图</h3>
            <div style="background: #f7fafc; padding: 10px; border-radius: 8px; margin-bottom: 10px;">
                <p style="color: #4a5568; font-size: 14px; margin: 0;">
                    💡 <strong>图表操作提示：</strong>
                    <span style="margin-left: 10px;">🖱️ <strong>鼠标滚轮</strong>：缩放图表</span>
                    <span style="margin-left: 15px;">👆 <strong>按住拖动</strong>：平移查看</span>
                    <span style="margin-left: 15px;">🔄 <strong>双击</strong>：重置视图</span>
                </p>
            </div>
            <div class="chart-container">
                <canvas id="{chart_id}"></canvas>
            </div>
        </div>

        <script>
        (function() {{
            const ctx = document.getElementById('{chart_id}').getContext('2d');
            new Chart(ctx, {{
                type: 'line',
                data: {{
                    datasets: [
                        {{
                            label: '发送 (Send)',
                            data: {json.dumps(send_points)},
                            borderColor: '#4299e1',
                            backgroundColor: 'rgba(66, 153, 225, 0.1)',
                            borderWidth: 2,
                            pointRadius: 4,
                            pointHoverRadius: 7,
                            fill: false,
                            tension: 0,
                            stepped: false
                        }},
                        {{
                            label: '接收 (Recv)',
                            data: {json.dumps(recv_points)},
                            borderColor: '#48bb78',
                            backgroundColor: 'rgba(72, 187, 120, 0.1)',
                            borderWidth: 2,
                            pointRadius: 4,
                            pointHoverRadius: 7,
                            fill: false,
                            tension: 0,
                            stepped: false
                        }}
                    ]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    interaction: {{
                        mode: 'nearest',
                        intersect: false,
                        axis: 'x'
                    }},
                    plugins: {{
                        legend: {{
                            display: true,
                            position: 'top',
                        }},
                        tooltip: {{
                            callbacks: {{
                                label: function(context) {{
                                    let label = context.dataset.label || '';
                                    if (label) {{
                                        label += ': ';
                                    }}
                                    if (context.parsed.y !== null) {{
                                        label += context.parsed.y + ' bytes';
                                    }}
                                    return label;
                                }}
                            }}
                        }},
                        zoom: {{
                            zoom: {{
                                wheel: {{
                                    enabled: true,
                                    speed: 0.1
                                }},
                                pinch: {{
                                    enabled: true
                                }},
                                mode: 'xy'
                            }},
                            pan: {{
                                enabled: true,
                                mode: 'xy'
                            }},
                            limits: {{
                                x: {{min: 'original', max: 'original'}},
                                y: {{min: 'original', max: 'original'}}
                            }}
                        }}
                    }},
                    scales: {{
                        y: {{
                            beginAtZero: true,
                            title: {{
                                display: true,
                                text: '包大小 (bytes)'
                            }}
                        }},
                        x: {{
                            type: 'time',
                            time: {{
                                unit: 'second',
                                displayFormats: {{
                                    second: 'HH:mm:ss',
                                    minute: 'HH:mm',
                                    hour: 'HH:mm'
                                }},
                                tooltipFormat: 'yyyy-MM-dd HH:mm:ss'
                            }},
                            title: {{
                                display: true,
                                text: '时间'
                            }},
                            ticks: {{
                                maxRotation: 45,
                                minRotation: 45,
                                autoSkip: true,
                                maxTicksLimit: 20
                            }}
                        }}
                    }}
                }}
            }});
        }})();
        </script>
        '''

        return html

    def _format_bytes(self, bytes_val: int) -> str:
        """格式化字节数"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_val < 1024.0:
                return f"{bytes_val:.2f} {unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.2f} PB"

    def _generate_summary_table(self, sorted_ips: List) -> str:
        """生成IP->SNI/DNS汇总表格"""
        html = '''
        <div class="summary-table-section">
            <h2>📋 IP与域名关联汇总表</h2>
            <table class="ip-dns-table">
                <thead>
                    <tr>
                        <th style="width: 10%;">远程IP</th>
                        <th style="width: 8%;">位置</th>
                        <th style="width: 12%;">流量模式</th>
                        <th style="width: 25%;">TLS SNI</th>
                        <th style="width: 25%;">DNS域名</th>
                        <th style="width: 10%;">威胁情报</th>
                        <th style="width: 5%;">包数</th>
                    </tr>
                </thead>
                <tbody>
        '''

        for ip, analysis in sorted_ips:
            ioc_data = analysis.get('ioc', {})

            # 流量模式信息
            traffic_pattern = analysis.get('traffic_pattern', {})
            pattern_type = traffic_pattern.get('pattern', 'unknown')
            pattern_desc = traffic_pattern.get('description', '未知')

            # 流量模式的颜色映射（同上）
            pattern_colors = {
                'heartbeat': '#f6ad55',
                'download': '#48bb78',
                'upload': '#4299e1',
                'blocked': '#e53e3e',
                'recv_only': '#9f7aea',
                'interactive': '#38b2ac',
                'bulk_transfer': '#ed8936',
                'request_response': '#667eea',
                'scan_probe': '#fc8181',
                'beaconing': '#c53030',
                'data_exfiltration': '#dd6b20',
                'slow_drip': '#805ad5',
                'burst_activity': '#d69e2e',
                'asymmetric_interactive': '#3182ce',
                'connection_test': '#718096',
                'large_transfer': '#2c7a7b',
                'keep_alive': '#68d391',
                'mixed': '#a0aec0',
                'unknown': '#cbd5e0'
            }

            pattern_icons = {
                'heartbeat': '💓',
                'download': '⬇️',
                'upload': '⬆️',
                'blocked': '🚫',
                'recv_only': '📥',
                'interactive': '💬',
                'bulk_transfer': '📦',
                'request_response': '🔄',
                'scan_probe': '🔍',
                'beaconing': '🚨',
                'data_exfiltration': '⚠️',
                'slow_drip': '💧',
                'burst_activity': '💥',
                'asymmetric_interactive': '⚖️',
                'connection_test': '🔌',
                'large_transfer': '📤',
                'keep_alive': '🔗',
                'mixed': '🔀',
                'unknown': '❓'
            }

            pattern_color = pattern_colors.get(pattern_type, '#cbd5e0')
            pattern_icon = pattern_icons.get(pattern_type, '❓')

            pattern_cell = f'<span style="background: {pattern_color}; color: white; padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: bold; display: inline-block;">{pattern_icon} {pattern_desc}</span>'

            # IP列，带周期性标记和IOC标记
            ip_cell = f'<span class="ip-column">{ip}</span>'
            if analysis['is_suspicious']:
                ip_cell += '<span class="periodic-indicator">⚠️ 周期性</span>'
            if ioc_data.get('ip_threat', False):
                ip_cell += '<span class="periodic-indicator" style="background: #c53030; color: white; margin-left: 4px;">🚨 IOC</span>'

            # 地理位置列
            geo_data = analysis.get('geo', {})
            if geo_data.get('success', False):
                is_china = geo_data.get('is_china', False)
                country_code = geo_data.get('country_code', '')
                location_type = geo_data.get('location_type', '未知')

                if is_china:
                    geo_cell = f'<span style="background: #48bb78; color: white; padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: bold;">🇨🇳 {location_type}</span>'
                else:
                    geo_cell = f'<span style="background: #ed8936; color: white; padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: bold;">🌍 {location_type}</span>'
            else:
                geo_cell = '<span style="color: #a0aec0; font-size: 11px;">未知</span>'

            # SNI列（带IOC标记）
            if analysis['sni_names']:
                sni_cell = '<div class="domain-list">'
                for sni in analysis['sni_names']:
                    if sni in ioc_data.get('sni_threats', {}):
                        sni_cell += f'<span class="domain-item" style="background: #fed7d7; color: #c53030; font-weight: bold;">🚨 {sni}</span>'
                    else:
                        sni_cell += f'<span class="domain-item">{sni}</span>'
                sni_cell += '</div>'
            else:
                sni_cell = '<span class="no-domain">无SNI记录</span>'

            # DNS列（带IOC标记）
            if analysis['dns_names']:
                dns_cell = '<div class="domain-list">'
                for dns in analysis['dns_names']:
                    if dns in ioc_data.get('dns_threats', {}):
                        dns_cell += f'<span class="domain-item" style="background: #fed7d7; color: #c53030; font-weight: bold;">🚨 {dns}</span>'
                    else:
                        dns_cell += f'<span class="domain-item">{dns}</span>'
                dns_cell += '</div>'
            else:
                dns_cell = '<span class="no-domain">无DNS记录</span>'

            # 威胁情报列
            threat_indicators = []
            if ioc_data.get('ip_threat', False):
                threat_indicators.append('IP')
            if ioc_data.get('sni_threats'):
                threat_indicators.append(
                    f'SNI({len(ioc_data["sni_threats"])})')
            if ioc_data.get('dns_threats'):
                threat_indicators.append(
                    f'DNS({len(ioc_data["dns_threats"])})')

            if threat_indicators:
                threat_cell = f'<span style="background: #c53030; color: white; padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: bold;">{", ".join(threat_indicators)}</span>'
            else:
                threat_cell = '<span style="color: #a0aec0;">-</span>'

            # 包数列
            packet_count = analysis['packet_count']

            html += f'''
                    <tr>
                        <td>{ip_cell}</td>
                        <td style="text-align: center;">{geo_cell}</td>
                        <td>{pattern_cell}</td>
                        <td>{sni_cell}</td>
                        <td>{dns_cell}</td>
                        <td style="text-align: center;">{threat_cell}</td>
                        <td style="text-align: center; font-weight: 600;">{packet_count}</td>
                    </tr>
            '''

        html += '''
                </tbody>
            </table>
        </div>
        '''

        return html

    def _generate_html_footer(self) -> str:
        """生成HTML尾部"""
        return '''
        <div class="footer">
            <p>网络流量分析工具 v1.0 | 基于周期性通讯模式的C2检测</p>
            <p style="margin-top: 10px; font-size: 12px;">
                ⚠️ 本报告仅供参考，被标记的IP需要结合其他信息进一步分析确认
            </p>
        </div>
    </div>
</body>
</html>
'''


def main():
    parser = argparse.ArgumentParser(
        description='网络流量分析工具 - 检测C2恶意软件通讯',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
示例用法:
  python analyzer.py capture_stats.json
  python analyzer.py capture_stats.json -o report.html
  python analyzer.py capture_stats.json --tolerance 0.2
  python analyzer.py capture_stats.json --otx-api-key YOUR_API_KEY

  # 使用代理查询GeoIP (支持ip-api.com批量查询)
  python analyzer.py capture_stats.json --proxy
  python analyzer.py capture_stats.json --proxy --proxy-host 127.0.0.1 --proxy-port 1080

说明:
  通过分析流量的周期性特征（jitter模式）检测潜在的C2通讯。
  C2通讯通常表现为固定间隔发送心跳包或接收指令。

  使用OTX威胁情报库进行IOC匹配（可选）。
  如果提供--otx-api-key参数，将对IP、SNI、DNS进行威胁情报查询。
  OTX API密钥可在 https://otx.alienvault.com 免费获取。

  GeoIP查询功能:
  - 使用ip-api.com的批量API，每次最多查询10个IP，大幅提升查询速度
  - 支持HTTP代理，可通过--proxy参数启用
  - 自动缓存查询结果，避免重复查询相同IP
  - 支持国内/国外地理位置判断，帮助识别可疑通讯
        '''
    )

    parser.add_argument('json_file', help='输入的JSON文件路径')
    parser.add_argument('-o', '--output', default='traffic_report.html',
                        help='输出HTML报告文件名 (默认: traffic_report.html)')
    parser.add_argument('-t', '--tolerance', type=float, default=0.3,
                        help='周期性检测的容差系数 (0-1, 默认: 0.3, 越小越严格)')
    parser.add_argument('--otx-api-key', default='',
                        help='AlienVault OTX API密钥 (可选，用于IOC威胁情报查询)')
    parser.add_argument('--proxy', action='store_true',
                        help='使用代理进行GeoIP查询')
    parser.add_argument('--proxy-host', default='',
                        help='代理服务器地址 (如: 127.0.0.1)')
    parser.add_argument('--proxy-port', type=int, default=0,
                        help='代理服务器端口 (如: 1080)')

    args = parser.parse_args()

    # 创建OTX检查器
    otx_checker = OTXChecker(args.otx_api_key)
    if otx_checker.enabled:
        print(f"[+] OTX威胁情报查询已启用")
    else:
        print(f"[!] 未提供OTX API密钥，跳过IOC匹配 (使用 --otx-api-key 启用)")

    # 创建GeoIP检查器（支持代理）
    if args.proxy:
        if args.proxy_host and args.proxy_port:
            geo_checker = GeoIPChecker(
                use_proxy=True, proxy_host=args.proxy_host, proxy_port=args.proxy_port)
        else:
            geo_checker = GeoIPChecker(use_proxy=True)  # 使用系统代理
    else:
        geo_checker = GeoIPChecker()

    # 创建分析器
    analyzer = TrafficAnalyzer(args.json_file, otx_checker, geo_checker)

    # 加载数据
    analyzer.load_data()

    # 分析流量
    analyzer.analyze_all()

    # 生成报告 - 为所有IP生成报告
    if analyzer.all_results:
        analyzer.generate_html_report(args.output)
        print(f"\n[+] 完成！请在浏览器中打开 {args.output} 查看报告")
    else:
        print("\n[+] 没有足够的数据生成报告")
        print("    请确保JSON文件中有有效的流量记录")


if __name__ == '__main__':
    main()
