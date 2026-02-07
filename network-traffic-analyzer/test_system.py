#!/usr/bin/env python
"""
网络流量分析平台 - 快速测试脚本
用于验证系统核心功能
"""

import asyncio
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path

# 添加项目根目录到路径
sys.path.insert(0, str(Path(__file__).parent))

from sqlalchemy.ext.asyncio import AsyncSession
from models.database import Dataset, Flow, DnsEvent, Alert
from models.db_session import get_session, init_db


async def test_database():
    """测试数据库连接"""
    print("=" * 60)
    print("测试 1: 数据库连接")
    print("=" * 60)
    
    try:
        await init_db()
        print("✓ 数据库初始化成功")
        
        async with get_session() as session:
            result = await session.execute("SELECT 1")
            print("✓ 数据库查询成功")
        
        return True
    except Exception as e:
        print(f"✗ 数据库测试失败: {e}")
        return False


async def test_create_dataset():
    """测试创建数据集"""
    print("\n" + "=" * 60)
    print("测试 2: 创建数据集")
    print("=" * 60)
    
    try:
        async with get_session() as session:
            dataset = Dataset(
                name="测试数据集",
                filename="test.pcap",
                file_path="/data/pcap/test.pcap",
                file_size=1024 * 1024,
                status="pending",
                progress=0.0
            )
            session.add(dataset)
            await session.commit()
            await session.refresh(dataset)
            
            print(f"✓ 数据集创建成功: {dataset.id}")
            print(f"  名称: {dataset.name}")
            print(f"  状态: {dataset.status}")
            
            return dataset.id
    except Exception as e:
        print(f"✗ 创建数据集失败: {e}")
        return None


async def test_create_flows(dataset_id: str):
    """测试创建流量记录"""
    print("\n" + "=" * 60)
    print("测试 3: 创建流量记录")
    print("=" * 60)
    
    try:
        async with get_session() as session:
            # 创建测试流量
            flows = []
            base_time = datetime.utcnow()
            
            for i in range(5):
                flow = Flow(
                    dataset_id=dataset_id,
                    flow_key=f"tcp_192.168.1.{10+i}_192.168.1.100_12345_{80+i}",
                    src_ip=f"192.168.1.{10+i}",
                    dst_ip="192.168.1.100",
                    src_port=12345 + i,
                    dst_port=80 + i,
                    protocol=6,  # TCP
                    ts_start=base_time + timedelta(seconds=i*10),
                    ts_end=base_time + timedelta(seconds=i*10+5),
                    duration=5.0,
                    packets_up=100,
                    packets_down=80,
                    bytes_up=10000,
                    bytes_down=8000,
                    state="ESTABLISHED",
                    app_protocol="HTTP"
                )
                flows.append(flow)
            
            session.add_all(flows)
            await session.commit()
            
            print(f"✓ 创建了 {len(flows)} 条流量记录")
            for flow in flows[:3]:
                print(f"  {flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port}")
            
            return True
    except Exception as e:
        print(f"✗ 创建流量失败: {e}")
        return False


async def test_create_dns_events(dataset_id: str):
    """测试创建 DNS 事件"""
    print("\n" + "=" * 60)
    print("测试 4: 创建 DNS 事件")
    print("=" * 60)
    
    try:
        async with get_session() as session:
            dns_events = [
                DnsEvent(
                    dataset_id=dataset_id,
                    timestamp=datetime.utcnow(),
                    src_ip="192.168.1.10",
                    dst_ip="8.8.8.8",
                    query_name="www.example.com",
                    query_type="A",
                    response_code=0,
                    answers=["93.184.216.34"],
                    ttl=3600,
                    query_length=17,
                    subdomain_count=1,
                    entropy=3.2
                ),
                DnsEvent(
                    dataset_id=dataset_id,
                    timestamp=datetime.utcnow(),
                    src_ip="192.168.1.10",
                    dst_ip="8.8.8.8",
                    query_name="very-long-suspicious-domain-name-with-random-chars-abc123xyz.example.com",
                    query_type="A",
                    response_code=3,  # NXDOMAIN
                    answers=[],
                    ttl=0,
                    query_length=75,
                    subdomain_count=3,
                    entropy=4.5
                )
            ]
            
            session.add_all(dns_events)
            await session.commit()
            
            print(f"✓ 创建了 {len(dns_events)} 条 DNS 事件")
            for event in dns_events:
                print(f"  {event.query_name} [{event.query_type}] -> {event.response_code}")
            
            return True
    except Exception as e:
        print(f"✗ 创建 DNS 事件失败: {e}")
        return False


async def test_create_alerts(dataset_id: str):
    """测试创建告警"""
    print("\n" + "=" * 60)
    print("测试 5: 创建告警")
    print("=" * 60)
    
    try:
        async with get_session() as session:
            alerts = [
                Alert(
                    dataset_id=dataset_id,
                    alert_type="port_scan",
                    severity="high",
                    title="检测到端口扫描",
                    description="来自 192.168.1.10 的主机在 60 秒内扫描了 15 个端口",
                    src_ip="192.168.1.10",
                    dst_ip="192.168.1.100",
                    ts_start=datetime.utcnow(),
                    ts_end=datetime.utcnow(),
                    score=8.5,
                    evidence={"scanned_ports": [80, 443, 22, 21, 3389]},
                    status="open"
                ),
                Alert(
                    dataset_id=dataset_id,
                    alert_type="dns_tunnel",
                    severity="medium",
                    title="疑似 DNS 隧道",
                    description="检测到异常的 DNS 查询特征: 高熵值域名",
                    src_ip="192.168.1.10",
                    dst_ip="8.8.8.8",
                    ts_start=datetime.utcnow(),
                    ts_end=datetime.utcnow(),
                    score=6.5,
                    evidence={"entropy": 4.5, "query_length": 75},
                    status="open"
                )
            ]
            
            session.add_all(alerts)
            await session.commit()
            
            print(f"✓ 创建了 {len(alerts)} 条告警")
            for alert in alerts:
                print(f"  [{alert.severity.upper()}] {alert.title}")
            
            return True
    except Exception as e:
        print(f"✗ 创建告警失败: {e}")
        return False


async def test_query_data(dataset_id: str):
    """测试数据查询"""
    print("\n" + "=" * 60)
    print("测试 6: 数据查询")
    print("=" * 60)
    
    try:
        async with get_session() as session:
            # 查询数据集
            from sqlalchemy import select
            
            result = await session.execute(select(Dataset).where(Dataset.id == dataset_id))
            dataset = result.scalar_one_or_none()
            print(f"✓ 数据集查询成功: {dataset.name}")
            
            # 查询流量
            result = await session.execute(select(Flow).where(Flow.dataset_id == dataset_id))
            flows = result.scalars().all()
            print(f"✓ 流量查询成功: {len(flows)} 条记录")
            
            # 查询 DNS 事件
            result = await session.execute(select(DnsEvent).where(DnsEvent.dataset_id == dataset_id))
            dns_events = result.scalars().all()
            print(f"✓ DNS 事件查询成功: {len(dns_events)} 条记录")
            
            # 查询告警
            result = await session.execute(select(Alert).where(Alert.dataset_id == dataset_id))
            alerts = result.scalars().all()
            print(f"✓ 告警查询成功: {len(alerts)} 条记录")
            
            return True
    except Exception as e:
        print(f"✗ 数据查询失败: {e}")
        return False


async def test_cleanup(dataset_id: str):
    """清理测试数据"""
    print("\n" + "=" * 60)
    print("测试 7: 清理测试数据")
    print("=" * 60)
    
    try:
        async with get_session() as session:
            from sqlalchemy import delete
            
            # 删除告警
            await session.execute(delete(Alert).where(Alert.dataset_id == dataset_id))
            
            # 删除 DNS 事件
            await session.execute(delete(DnsEvent).where(DnsEvent.dataset_id == dataset_id))
            
            # 删除流量
            await session.execute(delete(Flow).where(Flow.dataset_id == dataset_id))
            
            # 删除数据集
            await session.execute(delete(Dataset).where(Dataset.id == dataset_id))
            
            await session.commit()
            
            print("✓ 测试数据清理完成")
            return True
    except Exception as e:
        print(f"✗ 清理失败: {e}")
        return False


async def main():
    """主测试流程"""
    print("\n")
    print("╔" + "═" * 58 + "╗")
    print("║" + " " * 15 + "网络流量分析平台 - 测试套件" + " " * 15 + "║")
    print("╚" + "═" * 58 + "╝")
    
    # 测试数据库连接
    if not await test_database():
        print("\n✗ 数据库连接失败,测试终止")
        return
    
    # 创建测试数据集
    dataset_id = await test_create_dataset()
    if not dataset_id:
        print("\n✗ 创建数据集失败,测试终止")
        return
    
    # 运行测试
    tests = [
        ("创建流量记录", test_create_flows(dataset_id)),
        ("创建 DNS 事件", test_create_dns_events(dataset_id)),
        ("创建告警", test_create_alerts(dataset_id)),
        ("数据查询", test_query_data(dataset_id)),
    ]
    
    passed = 0
    for name, test in tests:
        if await test:
            passed += 1
    
    # 清理测试数据
    await test_cleanup(dataset_id)
    
    # 测试总结
    print("\n" + "=" * 60)
    print("测试总结")
    print("=" * 60)
    print(f"通过: {passed + 2}/{len(tests) + 2} 项测试")
    
    if passed == len(tests):
        print("\n✓ 所有测试通过!")
        print("\n系统已就绪,可以启动服务:")
        print("  python main.py")
        print("\n然后访问: http://localhost:8000")
    else:
        print(f"\n✗ 有 {len(tests) - passed} 项测试失败")
        print("请检查错误信息并修复问题")
    
    print("\n")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n测试中断")
    except Exception as e:
        print(f"\n✗ 测试异常: {e}")
        import traceback
        traceback.print_exc()
