"""
数据导出服务
"""
import csv
import json
import io
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from models.database import Flow, DnsEvent, HttpEvent, Alert, Dataset
from config.settings import get_settings

settings = get_settings()


class ExportService:
    """数据导出服务"""
    
    @staticmethod
    async def export_flows_csv(session: AsyncSession, dataset_id: str,
                               filters: Dict[str, Any] = None) -> str:
        """导出流数据为CSV"""
        query = select(Flow).where(Flow.dataset_id == dataset_id)
        
        if filters:
            if filters.get('src_ip'):
                query = query.where(Flow.src_ip == filters['src_ip'])
            if filters.get('dst_ip'):
                query = query.where(Flow.dst_ip == filters['dst_ip'])
            if filters.get('protocol'):
                query = query.where(Flow.protocol == filters['protocol'])
        
        result = await session.execute(query)
        flows = result.scalars().all()
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # 写入表头
        writer.writerow([
            'id', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol',
            'ts_start', 'ts_end', 'duration', 'packets_up', 'packets_down',
            'bytes_up', 'bytes_down', 'state', 'app_protocol'
        ])
        
        # 写入数据
        for flow in flows:
            writer.writerow([
                flow.id, flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port,
                flow.protocol, flow.ts_start, flow.ts_end, flow.duration,
                flow.packets_up, flow.packets_down, flow.bytes_up, flow.bytes_down,
                flow.state, flow.app_protocol
            ])
        
        return output.getvalue()
    
    @staticmethod
    async def export_flows_json(session: AsyncSession, dataset_id: str,
                                filters: Dict[str, Any] = None) -> str:
        """导出流数据为JSON"""
        query = select(Flow).where(Flow.dataset_id == dataset_id)
        
        if filters:
            if filters.get('src_ip'):
                query = query.where(Flow.src_ip == filters['src_ip'])
            if filters.get('dst_ip'):
                query = query.where(Flow.dst_ip == filters['dst_ip'])
        
        result = await session.execute(query)
        flows = result.scalars().all()
        
        data = []
        for flow in flows:
            data.append({
                'id': flow.id,
                'src_ip': flow.src_ip,
                'dst_ip': flow.dst_ip,
                'src_port': flow.src_port,
                'dst_port': flow.dst_port,
                'protocol': flow.protocol,
                'ts_start': flow.ts_start.isoformat() if flow.ts_start else None,
                'ts_end': flow.ts_end.isoformat() if flow.ts_end else None,
                'duration': flow.duration,
                'packets_up': flow.packets_up,
                'packets_down': flow.packets_down,
                'bytes_up': flow.bytes_up,
                'bytes_down': flow.bytes_down,
                'syn_count': flow.syn_count,
                'ack_count': flow.ack_count,
                'fin_count': flow.fin_count,
                'rst_count': flow.rst_count,
                'state': flow.state,
                'app_protocol': flow.app_protocol
            })
        
        return json.dumps(data, indent=2, ensure_ascii=False)
    
    @staticmethod
    async def export_alerts_csv(session: AsyncSession, dataset_id: str) -> str:
        """导出告警为CSV"""
        result = await session.execute(
            select(Alert).where(Alert.dataset_id == dataset_id)
        )
        alerts = result.scalars().all()
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        writer.writerow([
            'id', 'alert_type', 'severity', 'status', 'title', 'description',
            'ts_start', 'ts_end', 'src_ip', 'dst_ip', 'score', 'created_at'
        ])
        
        for alert in alerts:
            writer.writerow([
                alert.id, alert.alert_type.value if alert.alert_type else '',
                alert.severity.value if alert.severity else '', 
                alert.status.value if alert.status else '',
                alert.title, alert.description, alert.ts_start, alert.ts_end,
                alert.src_ip, alert.dst_ip, alert.score, alert.created_at
            ])
        
        return output.getvalue()
    
    @staticmethod
    async def export_dns_csv(session: AsyncSession, dataset_id: str) -> str:
        """导出DNS事件为CSV"""
        result = await session.execute(
            select(DnsEvent).where(DnsEvent.dataset_id == dataset_id)
        )
        events = result.scalars().all()
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        writer.writerow([
            'id', 'timestamp', 'src_ip', 'dst_ip', 'query_name', 'query_type',
            'is_response', 'response_code', 'qname_length', 'entropy'
        ])
        
        for event in events:
            writer.writerow([
                event.id, event.timestamp, event.src_ip, event.dst_ip,
                event.query_name, event.query_type, event.is_response,
                event.response_code, event.qname_length, event.entropy
            ])
        
        return output.getvalue()
    
    @staticmethod
    async def generate_html_report(session: AsyncSession, dataset_id: str) -> str:
        """生成HTML报告"""
        # 获取数据集信息
        result = await session.execute(
            select(Dataset).where(Dataset.id == dataset_id)
        )
        dataset = result.scalar_one_or_none()
        
        if not dataset:
            return "<html><body>Dataset not found</body></html>"
        
        # 获取告警
        alerts_result = await session.execute(
            select(Alert).where(Alert.dataset_id == dataset_id).order_by(Alert.severity.desc())
        )
        alerts = alerts_result.scalars().all()
        
        # 获取流统计
        flows_result = await session.execute(
            select(Flow).where(Flow.dataset_id == dataset_id)
        )
        flows = flows_result.scalars().all()
        
        # 统计协议分布
        proto_stats = {}
        for flow in flows:
            proto = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(flow.protocol, f'Other({flow.protocol})')
            proto_stats[proto] = proto_stats.get(proto, 0) + 1
        
        # 生成HTML
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>网络流量分析报告 - {dataset.name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }}
        h1 {{ color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin: 20px 0; }}
        .stat-card {{ background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; }}
        .stat-value {{ font-size: 2em; font-weight: bold; color: #007bff; }}
        .stat-label {{ color: #666; margin-top: 5px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #007bff; color: white; }}
        tr:hover {{ background: #f5f5f5; }}
        .severity-critical {{ color: #dc3545; font-weight: bold; }}
        .severity-high {{ color: #fd7e14; font-weight: bold; }}
        .severity-medium {{ color: #ffc107; }}
        .severity-low {{ color: #28a745; }}
        .alert-card {{ background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 10px 0; }}
        .alert-card.critical {{ background: #f8d7da; border-color: #dc3545; }}
        .alert-card.high {{ background: #ffe5d0; border-color: #fd7e14; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 网络流量分析报告</h1>
        
        <h2>📊 数据集概览</h2>
        <div class="stats">
            <div class="stat-card">
                <div class="stat-value">{dataset.total_packets:,}</div>
                <div class="stat-label">总数据包</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{dataset.total_bytes / 1024 / 1024:.2f} MB</div>
                <div class="stat-label">总流量</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{dataset.total_flows:,}</div>
                <div class="stat-label">总会话数</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{len(alerts)}</div>
                <div class="stat-label">安全告警</div>
            </div>
        </div>
        
        <p><strong>文件:</strong> {dataset.filename}</p>
        <p><strong>时间范围:</strong> {dataset.start_time} ~ {dataset.end_time}</p>
        
        <h2>📈 协议分布</h2>
        <table>
            <tr><th>协议</th><th>会话数</th><th>占比</th></tr>
            {"".join(f"<tr><td>{proto}</td><td>{count}</td><td>{count/len(flows)*100:.1f}%</td></tr>" for proto, count in sorted(proto_stats.items(), key=lambda x: x[1], reverse=True))}
        </table>
        
        <h2>🚨 安全告警 ({len(alerts)})</h2>
        {"".join(f'''
        <div class="alert-card {alert.severity.value if alert.severity else ''}">
            <strong class="severity-{alert.severity.value if alert.severity else 'low'}">[{alert.severity.value.upper() if alert.severity else 'UNKNOWN'}]</strong>
            <strong>{alert.title}</strong><br>
            <small>{alert.ts_start} - {alert.ts_end}</small><br>
            {alert.description}<br>
            <small>评分: {alert.score:.1f}</small>
        </div>
        ''' for alert in alerts[:20])}
        
        <p><em>报告生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</em></p>
    </div>
</body>
</html>
"""
        return html


export_service = ExportService()
