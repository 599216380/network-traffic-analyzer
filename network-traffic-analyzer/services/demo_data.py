"""
演示数据生成与导入
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import List

from sqlalchemy import select, func

from models.database import (
    Dataset, Flow, DnsEvent, HttpEvent, TlsEvent, Alert,
    TaskStatus, AlertSeverity, AlertStatus, AlertType
)
from models.db_session import get_db_context


DEMO_FILENAME = "demo.pcap"
DEMO_NAME = "演示数据集"


async def seed_demo_data() -> None:
    """如果演示数据不存在，则创建并写入数据库。"""
    async with get_db_context() as session:
        exists_result = await session.execute(
            select(func.count(Dataset.id)).where(
                (Dataset.filename == DEMO_FILENAME) | (Dataset.name == DEMO_NAME)
            )
        )
        if (exists_result.scalar() or 0) > 0:
            return

        now = datetime.utcnow()
        dataset_id = str(uuid.uuid4())

        flows: List[Flow] = []
        
        # 生成100条演示数据
        import random
        
        # 基础数据模板
        src_ips = [f"192.168.1.{i}" for i in range(10, 110)]
        dst_ips = [
            "8.8.8.8", "1.1.1.1", "93.184.216.34", "203.0.113.10", 
            "104.16.132.229", "142.250.185.206", "13.107.42.14",
            "172.217.164.110", "151.101.1.140", "52.84.150.20"
        ]
        protocols = [
            (6, "TCP", ["HTTP", "HTTPS", "TLS", "SSH", "FTP", "SMTP"]),
            (17, "UDP", ["DNS", "QUIC", "NTP"]),
            (1, "ICMP", [None])
        ]
        
        for i in range(100):
            src_ip = src_ips[i % 100]
            dst_ip = random.choice(dst_ips)
            proto_num, proto_name, apps = random.choice(protocols)
            app = random.choice(apps) if apps[0] else None
            
            # 根据协议选择端口
            if proto_num == 6:  # TCP
                if app == "HTTP":
                    dst_port = 80
                elif app in ["HTTPS", "TLS"]:
                    dst_port = 443
                elif app == "SSH":
                    dst_port = 22
                elif app == "FTP":
                    dst_port = 21
                elif app == "SMTP":
                    dst_port = 25
                else:
                    dst_port = random.randint(1024, 65535)
            elif proto_num == 17:  # UDP
                if app == "DNS":
                    dst_port = 53
                elif app == "NTP":
                    dst_port = 123
                else:
                    dst_port = random.randint(1024, 65535)
            else:  # ICMP
                dst_port = 0
            
            src_port = random.randint(49152, 65535)
            
            # 随机生成流量统计
            up_pkts = random.randint(5, 50)
            down_pkts = random.randint(5, 50)
            up_bytes = random.randint(1000, 50000)
            down_bytes = random.randint(1000, 50000)
            
            # 大部分连接是成功的，少数失败
            state = "established" if random.random() > 0.15 else "failed"
            
            # 时间分散在过去2小时内
            minutes_ago = random.randint(1, 120)
            
            flow_data = (src_ip, dst_ip, src_port, dst_port, proto_num, app, 
                        up_pkts, down_pkts, up_bytes, down_bytes, state, minutes_ago)
            
            (src_ip, dst_ip, src_port, dst_port, proto, app, up_pkts, down_pkts, up_bytes, down_bytes, state, minutes_ago) = flow_data
            ts_start = now - timedelta(minutes=minutes_ago)
            ts_end = ts_start + timedelta(seconds=up_pkts + down_pkts)
            duration = (ts_end - ts_start).total_seconds()
            flows.append(
                Flow(
                    dataset_id=dataset_id,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=proto,
                    ts_start=ts_start,
                    ts_end=ts_end,
                    duration=duration,
                    packets_up=up_pkts,
                    packets_down=down_pkts,
                    bytes_up=up_bytes,
                    bytes_down=down_bytes,
                    state=state,
                    app_protocol=app
                )
            )

        total_packets = sum(f.packets_up + f.packets_down for f in flows)
        total_bytes = sum(f.bytes_up + f.bytes_down for f in flows)
        start_time = min(f.ts_start for f in flows)
        end_time = max(f.ts_end for f in flows)

        dataset = Dataset(
            id=dataset_id,
            name=DEMO_NAME,
            filename=DEMO_FILENAME,
            filepath="demo://generated",
            file_size=2_048_000,
            status=TaskStatus.DONE,
            progress=100.0,
            total_packets=total_packets,
            total_bytes=total_bytes,
            total_flows=len(flows),
            start_time=start_time,
            end_time=end_time
        )

        session.add(dataset)
        session.add_all(flows)
        await session.flush()

        # DNS 事件
        dns_flow = flows[0]
        dns_events = [
            DnsEvent(
                dataset_id=dataset_id,
                flow_id=dns_flow.id,
                timestamp=dns_flow.ts_start + timedelta(seconds=1),
                src_ip=dns_flow.src_ip,
                dst_ip=dns_flow.dst_ip,
                transaction_id=1234,
                query_name="example.com",
                query_type="A",
                is_response=False,
                response_code=None,
                qname_length=len("example.com"),
                subdomain_count=1,
                entropy=2.9
            ),
            DnsEvent(
                dataset_id=dataset_id,
                flow_id=dns_flow.id,
                timestamp=dns_flow.ts_start + timedelta(seconds=2),
                src_ip=dns_flow.dst_ip,
                dst_ip=dns_flow.src_ip,
                transaction_id=1234,
                query_name="example.com",
                query_type="A",
                is_response=True,
                response_code="NOERROR",
                answers=[{"type": "A", "value": "93.184.216.34"}],
                ttl=300,
                qname_length=len("example.com"),
                subdomain_count=1,
                entropy=2.9
            ),
            DnsEvent(
                dataset_id=dataset_id,
                flow_id=flows[9].id,
                timestamp=flows[9].ts_start + timedelta(seconds=1),
                src_ip=flows[9].src_ip,
                dst_ip=flows[9].dst_ip,
                transaction_id=4455,
                query_name="l9xqv0ab.example.net",
                query_type="TXT",
                is_response=False,
                response_code=None,
                qname_length=len("l9xqv0ab.example.net"),
                subdomain_count=3,
                entropy=3.8
            )
        ]

        # HTTP 事件
        http_flow = flows[2]
        http_events = [
            HttpEvent(
                dataset_id=dataset_id,
                flow_id=http_flow.id,
                timestamp=http_flow.ts_start + timedelta(seconds=2),
                src_ip=http_flow.src_ip,
                dst_ip=http_flow.dst_ip,
                src_port=http_flow.src_port,
                dst_port=http_flow.dst_port,
                method="GET",
                host="example.com",
                uri="/index.html",
                user_agent="Mozilla/5.0",
                status_code=200,
                content_type="text/html",
                content_length=10240
            ),
            HttpEvent(
                dataset_id=dataset_id,
                flow_id=http_flow.id,
                timestamp=http_flow.ts_start + timedelta(seconds=4),
                src_ip=http_flow.src_ip,
                dst_ip=http_flow.dst_ip,
                src_port=http_flow.src_port,
                dst_port=http_flow.dst_port,
                method="POST",
                host="example.com",
                uri="/login",
                user_agent="Mozilla/5.0",
                status_code=401,
                content_type="application/json",
                content_length=512
            )
        ]

        # TLS 事件
        tls_flow = flows[1]
        tls_events = [
            TlsEvent(
                dataset_id=dataset_id,
                flow_id=tls_flow.id,
                timestamp=tls_flow.ts_start + timedelta(seconds=1),
                src_ip=tls_flow.src_ip,
                dst_ip=tls_flow.dst_ip,
                src_port=tls_flow.src_port,
                dst_port=tls_flow.dst_port,
                sni="example.com",
                ja3_hash="72a589da586844d7f0818ce684948eea",
                tls_version="TLS1.3",
                cert_subject="CN=example.com",
                cert_issuer="CN=Example CA"
            )
        ]

        session.add_all(dns_events)
        await session.flush()
        session.add_all(http_events)
        session.add_all(tls_events)

        alerts = [
            Alert(
                dataset_id=dataset_id,
                alert_type=AlertType.BRUTE_FORCE,
                severity=AlertSeverity.HIGH,
                status=AlertStatus.OPEN,
                title="疑似SSH暴力破解",
                description="同一目标端口在短时间内出现多次失败登录尝试",
                ts_start=flows[3].ts_start,
                ts_end=flows[6].ts_end,
                src_ip=flows[3].src_ip,
                dst_ip=flows[3].dst_ip,
                dst_ports=[22],
                score=88.5,
                indicators={"failed_attempts": 12, "window_seconds": 300},
                related_flow_ids=[flows[3].id, flows[4].id, flows[5].id, flows[6].id],
                rule_id="brute_force",
                rule_name="暴力破解检测"
            ),
            Alert(
                dataset_id=dataset_id,
                alert_type=AlertType.DNS_TUNNEL,
                severity=AlertSeverity.MEDIUM,
                status=AlertStatus.OPEN,
                title="疑似DNS隧道通信",
                description="检测到高熵、长域名的DNS查询",
                ts_start=dns_events[2].timestamp,
                ts_end=dns_events[2].timestamp,
                src_ip=dns_events[2].src_ip,
                dst_ip=dns_events[2].dst_ip,
                score=62.0,
                indicators={"entropy": 3.8, "qname_length": dns_events[2].qname_length},
                related_dns_ids=[dns_events[2].id],
                rule_id="dns_tunnel",
                rule_name="DNS隧道检测"
            )
        ]

        session.add_all(alerts)
        await session.commit()
