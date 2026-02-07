"""
PCAP导入服务 - 处理文件上传、解析和入库
"""
import os
import uuid
import asyncio
from datetime import datetime
from typing import Optional, Tuple
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from models.database import Dataset, Flow, DnsEvent, HttpEvent, TlsEvent, Alert, TaskStatus
from models.db_session import get_db_context
from parsers.pcap_parser import PcapParser
from parsers.flow_aggregator import FlowAggregator
from detection import create_default_engine, DetectionResult
from config.settings import get_settings

settings = get_settings()


class PcapImportService:
    """PCAP导入服务"""
    
    def __init__(self):
        self.detection_engine = create_default_engine()
    
    async def create_import_task(self, filename: str, filepath: str, 
                                  name: Optional[str] = None) -> str:
        """
        创建导入任务
        
        Args:
            filename: 原始文件名
            filepath: 文件保存路径
            name: 数据集名称
        
        Returns:
            dataset_id
        """
        dataset_id = str(uuid.uuid4())
        
        async with get_db_context() as session:
            # 创建数据集记录
            file_size = os.path.getsize(filepath) if os.path.exists(filepath) else 0
            
            dataset = Dataset(
                id=dataset_id,
                name=name or filename,
                filename=filename,
                filepath=filepath,
                file_size=file_size,
                status=TaskStatus.PENDING,
                progress=0.0
            )
            
            session.add(dataset)
            await session.commit()
        
        return dataset_id
    
    async def process_import(self, dataset_id: str) -> bool:
        """
        执行导入处理
        
        Args:
            dataset_id: 数据集ID
        
        Returns:
            是否成功
        """
        try:
            async with get_db_context() as session:
                # 获取数据集
                result = await session.execute(
                    select(Dataset).where(Dataset.id == dataset_id)
                )
                dataset = result.scalar_one_or_none()
                
                if not dataset:
                    return False
                
                # 更新状态
                dataset.status = TaskStatus.RUNNING
                dataset.progress = 0.0
                await session.commit()
                
                filepath = dataset.filepath
            
            # 解析PCAP
            parser = PcapParser(filepath)
            aggregator = FlowAggregator(
                idle_timeout=settings.FLOW_IDLE_TIMEOUT,
                active_timeout=settings.FLOW_ACTIVE_TIMEOUT
            )
            
            # 解析并聚合
            packet_count = 0
            min_time = None
            max_time = None
            
            for packet in parser.parse():
                packet_count += 1
                aggregator.process_packet(packet)
                
                # 更新时间范围
                if min_time is None or packet.timestamp < min_time:
                    min_time = packet.timestamp
                if max_time is None or packet.timestamp > max_time:
                    max_time = packet.timestamp
                
                # 定期更新进度
                if packet_count % 10000 == 0:
                    await self._update_progress(dataset_id, min(packet_count / 100000, 0.5) * 100)
            
            # 完成聚合
            aggregator.flush()
            
            # 更新进度
            await self._update_progress(dataset_id, 60)
            
            # 入库
            async with get_db_context() as session:
                # 入库flows
                flow_id_map = await self._save_flows(session, dataset_id, aggregator.completed_flows)
                
                await self._update_progress(dataset_id, 70)
                
                # 入库DNS事件
                dns_id_map = await self._save_dns_events(session, dataset_id, aggregator.dns_events)
                
                await self._update_progress(dataset_id, 80)
                
                # 入库HTTP事件
                http_id_map = await self._save_http_events(session, dataset_id, aggregator.http_events)
                
                # 入库TLS事件
                await self._save_tls_events(session, dataset_id, aggregator.tls_events)
                
                await self._update_progress(dataset_id, 85)
                
                # 运行检测
                if settings.DETECTION_ENABLED:
                    # 获取已保存的flows（带ID）
                    flows_result = await session.execute(
                        select(Flow).where(Flow.dataset_id == dataset_id)
                    )
                    saved_flows = flows_result.scalars().all()
                    
                    dns_result = await session.execute(
                        select(DnsEvent).where(DnsEvent.dataset_id == dataset_id)
                    )
                    saved_dns = dns_result.scalars().all()
                    
                    http_result = await session.execute(
                        select(HttpEvent).where(HttpEvent.dataset_id == dataset_id)
                    )
                    saved_http = http_result.scalars().all()
                    
                    # 执行检测
                    detection_results = self.detection_engine.run_all(
                        saved_flows, saved_dns, saved_http
                    )
                    
                    await self._update_progress(dataset_id, 90)
                    
                    # 保存告警
                    await self._save_alerts(session, dataset_id, detection_results)
                
                await session.commit()
            
            # 更新数据集统计信息
            async with get_db_context() as session:
                result = await session.execute(
                    select(Dataset).where(Dataset.id == dataset_id)
                )
                dataset = result.scalar_one()
                
                dataset.status = TaskStatus.DONE
                dataset.progress = 100.0
                dataset.total_packets = packet_count
                dataset.total_bytes = aggregator.total_bytes
                dataset.total_flows = len(aggregator.completed_flows)
                dataset.start_time = min_time
                dataset.end_time = max_time
                
                await session.commit()
            
            return True
            
        except Exception as e:
            # 记录错误
            async with get_db_context() as session:
                result = await session.execute(
                    select(Dataset).where(Dataset.id == dataset_id)
                )
                dataset = result.scalar_one_or_none()
                
                if dataset:
                    dataset.status = TaskStatus.FAILED
                    dataset.error_message = str(e)
                    await session.commit()
            
            raise
    
    async def _update_progress(self, dataset_id: str, progress: float) -> None:
        """更新进度"""
        async with get_db_context() as session:
            await session.execute(
                update(Dataset).where(Dataset.id == dataset_id).values(progress=progress)
            )
            await session.commit()
    
    async def _save_flows(self, session: AsyncSession, dataset_id: str, 
                         flows: list) -> dict:
        """保存流记录"""
        id_map = {}
        
        for i, flow_record in enumerate(flows):
            flow = Flow(
                dataset_id=dataset_id,
                src_ip=flow_record.src_ip,
                dst_ip=flow_record.dst_ip,
                src_port=flow_record.src_port,
                dst_port=flow_record.dst_port,
                protocol=flow_record.protocol,
                ts_start=flow_record.ts_start,
                ts_end=flow_record.ts_end,
                duration=flow_record.duration,
                packets_up=flow_record.packets_up,
                packets_down=flow_record.packets_down,
                bytes_up=flow_record.bytes_up,
                bytes_down=flow_record.bytes_down,
                syn_count=flow_record.syn_count,
                ack_count=flow_record.ack_count,
                fin_count=flow_record.fin_count,
                rst_count=flow_record.rst_count,
                psh_count=flow_record.psh_count,
                state=flow_record.state,
                app_protocol=flow_record.app_protocol,
                first_packet_id=flow_record.first_packet_id,
                last_packet_id=flow_record.last_packet_id
            )
            session.add(flow)
            
            # 批量提交
            if (i + 1) % 1000 == 0:
                await session.flush()
        
        await session.flush()
        return id_map
    
    async def _save_dns_events(self, session: AsyncSession, dataset_id: str,
                               events: list) -> dict:
        """保存DNS事件"""
        id_map = {}
        
        for i, event in enumerate(events):
            dns_event = DnsEvent(
                dataset_id=dataset_id,
                timestamp=event.get('timestamp'),
                src_ip=event.get('src_ip', ''),
                dst_ip=event.get('dst_ip', ''),
                transaction_id=event.get('transaction_id'),
                query_name=event.get('query_name', ''),
                query_type=event.get('query_type'),
                is_response=event.get('is_response', False),
                response_code=event.get('response_code'),
                answers=event.get('answers'),
                ttl=event.get('answers', [{}])[0].get('ttl') if event.get('answers') else None,
                qname_length=event.get('qname_length', 0),
                subdomain_count=event.get('subdomain_count', 0),
                entropy=event.get('entropy'),
                packet_id=event.get('packet_id')
            )
            session.add(dns_event)
            
            if (i + 1) % 1000 == 0:
                await session.flush()
        
        await session.flush()
        return id_map
    
    async def _save_http_events(self, session: AsyncSession, dataset_id: str,
                                events: list) -> dict:
        """保存HTTP事件"""
        id_map = {}
        
        for i, event in enumerate(events):
            http_event = HttpEvent(
                dataset_id=dataset_id,
                timestamp=event.get('timestamp'),
                src_ip=event.get('src_ip', ''),
                dst_ip=event.get('dst_ip', ''),
                src_port=event.get('src_port', 0),
                dst_port=event.get('dst_port', 0),
                method=event.get('method'),
                host=event.get('host'),
                uri=event.get('uri'),
                user_agent=event.get('user_agent'),
                referer=event.get('referer'),
                content_type=event.get('content_type'),
                content_length=event.get('content_length'),
                status_code=event.get('status_code'),
                response_content_type=event.get('response_content_type'),
                response_content_length=event.get('response_content_length'),
                headers=event.get('headers'),
                packet_id=event.get('packet_id')
            )
            session.add(http_event)
            
            if (i + 1) % 1000 == 0:
                await session.flush()
        
        await session.flush()
        return id_map
    
    async def _save_tls_events(self, session: AsyncSession, dataset_id: str,
                               events: list) -> None:
        """保存TLS事件"""
        for i, event in enumerate(events):
            tls_event = TlsEvent(
                dataset_id=dataset_id,
                timestamp=event.get('timestamp'),
                src_ip=event.get('src_ip', ''),
                dst_ip=event.get('dst_ip', ''),
                src_port=event.get('src_port', 0),
                dst_port=event.get('dst_port', 0),
                sni=event.get('sni'),
                ja3_hash=event.get('ja3_hash'),
                tls_version=event.get('tls_version'),
                cipher_suites=event.get('cipher_suites'),
                extensions=event.get('extensions'),
                packet_id=event.get('packet_id')
            )
            session.add(tls_event)
            
            if (i + 1) % 1000 == 0:
                await session.flush()
        
        await session.flush()
    
    async def _save_alerts(self, session: AsyncSession, dataset_id: str,
                          results: list) -> None:
        """保存检测告警"""
        for result in results:
            alert = Alert(
                dataset_id=dataset_id,
                alert_type=result.alert_type,
                severity=result.severity,
                status='open',
                title=result.title,
                description=result.description,
                ts_start=result.ts_start,
                ts_end=result.ts_end,
                src_ip=result.src_ip,
                dst_ip=result.dst_ip,
                src_ips=result.src_ips if result.src_ips else None,
                dst_ips=result.dst_ips if result.dst_ips else None,
                dst_ports=result.dst_ports if result.dst_ports else None,
                score=result.score,
                indicators=result.indicators,
                evidence=result.evidence,
                related_flow_ids=result.related_flow_ids if result.related_flow_ids else None,
                related_dns_ids=result.related_dns_ids if result.related_dns_ids else None,
                related_http_ids=result.related_http_ids if result.related_http_ids else None,
                rule_id=result.rule_id,
                rule_name=result.rule_name
            )
            session.add(alert)
        
        await session.flush()


# 单例
import_service = PcapImportService()
