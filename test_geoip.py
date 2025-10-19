#!/usr/bin/env python3
"""
测试GeoIP批量查询功能
"""

import json
import sys
from analyzer import GeoIPChecker

def test_geoip():
    """测试GeoIP功能"""
    print("=== GeoIP批量查询测试 ===\n")

    # 测试IP列表
    test_ips = [
        "8.8.8.8",        # Google DNS
        "1.1.1.1",        # Cloudflare DNS
        "114.114.114.114", # 114 DNS (中国)
        "223.5.5.5",      # 阿里DNS (中国)
        "208.67.222.222", # OpenDNS
        "9.9.9.9",        # Quad9 DNS
        "8.26.56.26",     # Comodo DNS
        "208.67.220.220", # OpenDNS2
        "1.0.0.1",        # Cloudflare DNS2
        "149.112.112.112", # Quad9 DNS2
        "192.168.1.1",    # 内网IP
        "10.0.0.1"        # 内网IP
    ]

    print(f"测试IP数量: {len(test_ips)}")
    print("IP列表:", ", ".join(test_ips))
    print()

    # 测试不使用代理
    print("1. 测试不使用代理:")
    geo_checker = GeoIPChecker(use_proxy=False)
    results = geo_checker.check_batch_ips(test_ips)

    print(f"成功查询 {len(results)} 个IP")
    for ip, result in results.items():
        if result['success']:
            print(f"  {ip} -> {result['country']} ({result['location_type']}) - {result['isp']}")
        else:
            print(f"  {ip} -> 查询失败: {result.get('error', '未知错误')}")
    print()

    # 测试使用系统代理（如果有的话）
    print("2. 测试使用系统代理:")
    geo_checker_proxy = GeoIPChecker(use_proxy=True)
    results_proxy = geo_checker_proxy.check_batch_ips(test_ips[:5])  # 只测试前5个

    print(f"通过代理成功查询 {len(results_proxy)} 个IP")
    for ip, result in results_proxy.items():
        if result['success']:
            print(f"  {ip} -> {result['country']} ({result['location_type']})")
        else:
            print(f"  {ip} -> 查询失败: {result.get('error', '未知错误')}")
    print()

    # 测试缓存功能
    print("3. 测试缓存功能 (重复查询前3个IP):")
    cached_results = geo_checker.check_batch_ips(test_ips[:3])
    print(f"缓存查询结果数量: {len(cached_results)}")
    for ip, result in cached_results.items():
        print(f"  {ip} -> {result['country']} (应该直接从缓存获取)")
    print()

    print("=== 测试完成 ===")

if __name__ == "__main__":
    test_geoip()