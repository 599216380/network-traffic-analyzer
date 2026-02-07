"""
仪表盘与导出API
"""
from typing import Optional
from datetime import datetime, timedelta

from fastapi import APIRouter, HTTPException, Depends, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_

from models import (
    Dataset, Flow, DnsEvent, HttpEvent, Alert, 
    DashboardStats, get_db
)
from services.export_service import export_service

router = APIRouter(tags=["dashboard"])


@router.get("/dashboard", response_model=DashboardStats)
async def get_dashboard_stats(
    dataset_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """获取仪表盘统计数据"""
    
    # 数据集总数
    datasets_result = await db.execute(select(func.count(Dataset.id)))
    total_datasets = datasets_result.scalar()
    
    # 流量总数
    flows_query = select(func.count(Flow.id))
    bytes_query = select(func.sum(Flow.bytes_up + Flow.bytes_down))
    
    if dataset_id:
        flows_query = flows_query.where(Flow.dataset_id == dataset_id)
        bytes_query = bytes_query.where(Flow.dataset_id == dataset_id)
    
    flows_result = await db.execute(flows_query)
    total_flows = flows_result.scalar() or 0
    
    bytes_result = await db.execute(bytes_query)
    total_bytes = bytes_result.scalar() or 0
    
    # 告警统计
    alerts_query = select(func.count(Alert.id))
    if dataset_id:
        alerts_query = alerts_query.where(Alert.dataset_id == dataset_id)
    
    alerts_result = await db.execute(alerts_query)
    total_alerts = alerts_result.scalar() or 0
    
    # 按严重程度统计告警
    severity_query = select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)
    if dataset_id:
        severity_query = severity_query.where(Alert.dataset_id == dataset_id)
    
    severity_result = await db.execute(severity_query)
    alerts_by_severity = {
        row[0].value if row[0] else 'unknown': row[1]
        for row in severity_result.all()
    }
    
    # 按类型统计告警
    type_query = select(Alert.alert_type, func.count(Alert.id)).group_by(Alert.alert_type)
    if dataset_id:
        type_query = type_query.where(Alert.dataset_id == dataset_id)
    
    type_result = await db.execute(type_query)
    alerts_by_type = {
        row[0].value if row[0] else 'unknown': row[1]
        for row in type_result.all()
    }
    
    # Top源IP
    src_ip_query = (
        select(Flow.src_ip, func.sum(Flow.bytes_up + Flow.bytes_down).label('total'))
        .group_by(Flow.src_ip)
        .order_by(func.sum(Flow.bytes_up + Flow.bytes_down).desc())
        .limit(10)
    )
    if dataset_id:
        src_ip_query = src_ip_query.where(Flow.dataset_id == dataset_id)
    
    src_ip_result = await db.execute(src_ip_query)
    top_src_ips = [{'ip': row[0], 'bytes': row[1]} for row in src_ip_result.all()]
    
    # Top目的IP
    dst_ip_query = (
        select(Flow.dst_ip, func.sum(Flow.bytes_up + Flow.bytes_down).label('total'))
        .group_by(Flow.dst_ip)
        .order_by(func.sum(Flow.bytes_up + Flow.bytes_down).desc())
        .limit(10)
    )
    if dataset_id:
        dst_ip_query = dst_ip_query.where(Flow.dataset_id == dataset_id)
    
    dst_ip_result = await db.execute(dst_ip_query)
    top_dst_ips = [{'ip': row[0], 'bytes': row[1]} for row in dst_ip_result.all()]
    
    # Top域名
    domain_query = (
        select(DnsEvent.query_name, func.count(DnsEvent.id).label('count'))
        .where(DnsEvent.is_response == False)
        .group_by(DnsEvent.query_name)
        .order_by(func.count(DnsEvent.id).desc())
        .limit(10)
    )
    if dataset_id:
        domain_query = domain_query.where(DnsEvent.dataset_id == dataset_id)
    
    domain_result = await db.execute(domain_query)
    top_domains = [{'domain': row[0], 'count': row[1]} for row in domain_result.all()]
    
    # 协议分布
    proto_query = (
        select(Flow.protocol, func.count(Flow.id))
        .group_by(Flow.protocol)
    )
    if dataset_id:
        proto_query = proto_query.where(Flow.dataset_id == dataset_id)
    
    proto_result = await db.execute(proto_query)
    proto_map = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}
    protocol_distribution = {
        proto_map.get(row[0], f'Other({row[0]})'): row[1]
        for row in proto_result.all()
    }
    
    # 流量时间线（简化版）
    traffic_timeline = []
    
    return DashboardStats(
        total_datasets=total_datasets,
        total_flows=total_flows,
        total_bytes=total_bytes,
        total_alerts=total_alerts,
        alerts_by_severity=alerts_by_severity,
        alerts_by_type=alerts_by_type,
        top_src_ips=top_src_ips,
        top_dst_ips=top_dst_ips,
        top_domains=top_domains,
        protocol_distribution=protocol_distribution,
        traffic_timeline=traffic_timeline
    )


# Export Router
export_router = APIRouter(prefix="/export", tags=["export"])


@export_router.get("/flows/{dataset_id}/csv")
async def export_flows_csv(
    dataset_id: str,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    protocol: Optional[int] = None,
    db: AsyncSession = Depends(get_db)
):
    """导出流数据为CSV"""
    filters = {}
    if src_ip:
        filters['src_ip'] = src_ip
    if dst_ip:
        filters['dst_ip'] = dst_ip
    if protocol:
        filters['protocol'] = protocol
    
    csv_content = await export_service.export_flows_csv(db, dataset_id, filters)
    
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=flows_{dataset_id}.csv"}
    )


@export_router.get("/flows/{dataset_id}/json")
async def export_flows_json(
    dataset_id: str,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """导出流数据为JSON"""
    filters = {}
    if src_ip:
        filters['src_ip'] = src_ip
    if dst_ip:
        filters['dst_ip'] = dst_ip
    
    json_content = await export_service.export_flows_json(db, dataset_id, filters)
    
    return Response(
        content=json_content,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=flows_{dataset_id}.json"}
    )


@export_router.get("/alerts/{dataset_id}/csv")
async def export_alerts_csv(dataset_id: str, db: AsyncSession = Depends(get_db)):
    """导出告警为CSV"""
    csv_content = await export_service.export_alerts_csv(db, dataset_id)
    
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=alerts_{dataset_id}.csv"}
    )


@export_router.get("/dns/{dataset_id}/csv")
async def export_dns_csv(dataset_id: str, db: AsyncSession = Depends(get_db)):
    """导出DNS事件为CSV"""
    csv_content = await export_service.export_dns_csv(db, dataset_id)
    
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=dns_{dataset_id}.csv"}
    )


@export_router.get("/report/{dataset_id}/html")
async def export_html_report(dataset_id: str, db: AsyncSession = Depends(get_db)):
    """生成HTML分析报告"""
    html_content = await export_service.generate_html_report(db, dataset_id)
    
    return Response(
        content=html_content,
        media_type="text/html",
        headers={"Content-Disposition": f"attachment; filename=report_{dataset_id}.html"}
    )
