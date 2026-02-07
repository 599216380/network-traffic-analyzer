"""
仪表盘与统计API路由
"""
from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
from typing import Optional
from datetime import datetime, timedelta
import io

from models import get_db, Dataset, Flow, DnsEvent, HttpEvent, Alert
from models.database import AlertSeverity, AlertStatus
from services.export_service import export_service

router = APIRouter(prefix="/dashboard", tags=["仪表盘"])


@router.get("/overview")
async def get_dashboard_overview(db: AsyncSession = Depends(get_db)):
    """获取仪表盘总览"""
    # 数据集统计
    datasets_result = await db.execute(select(func.count(Dataset.id)))
    total_datasets = datasets_result.scalar() or 0
    
    # 流量统计
    flows_result = await db.execute(
        select(
            func.count(Flow.id),
            func.sum(Flow.bytes_up + Flow.bytes_down)
        )
    )
    flow_stats = flows_result.one()
    total_flows = flow_stats[0] or 0
    total_bytes = flow_stats[1] or 0
    
    # 告警统计
    alerts_result = await db.execute(select(func.count(Alert.id)))
    total_alerts = alerts_result.scalar() or 0
    
    # 开放告警
    open_alerts_result = await db.execute(
        select(func.count(Alert.id)).where(Alert.status == AlertStatus.OPEN)
    )
    open_alerts = open_alerts_result.scalar() or 0
    
    # 告警按严重程度
    severity_result = await db.execute(
        select(Alert.severity, func.count(Alert.id))
        .group_by(Alert.severity)
    )
    alerts_by_severity = {
        str(s.value) if s else 'unknown': c 
        for s, c in severity_result.all()
    }
    
    # 告警按类型
    type_result = await db.execute(
        select(Alert.alert_type, func.count(Alert.id))
        .group_by(Alert.alert_type)
    )
    alerts_by_type = {
        str(t.value) if t else 'unknown': c 
        for t, c in type_result.all()
    }
    
    # Top源IP（按流量）
    top_src_result = await db.execute(
        select(Flow.src_ip, func.sum(Flow.bytes_up + Flow.bytes_down).label('total'))
        .group_by(Flow.src_ip)
        .order_by(func.sum(Flow.bytes_up + Flow.bytes_down).desc())
        .limit(10)
    )
    top_src_ips = [{'ip': ip, 'bytes': int(b or 0)} for ip, b in top_src_result.all()]
    
    # Top目的IP
    top_dst_result = await db.execute(
        select(Flow.dst_ip, func.sum(Flow.bytes_up + Flow.bytes_down).label('total'))
        .group_by(Flow.dst_ip)
        .order_by(func.sum(Flow.bytes_up + Flow.bytes_down).desc())
        .limit(10)
    )
    top_dst_ips = [{'ip': ip, 'bytes': int(b or 0)} for ip, b in top_dst_result.all()]
    
    # Top域名
    top_domains_result = await db.execute(
        select(DnsEvent.query_name, func.count(DnsEvent.id).label('count'))
        .where(DnsEvent.is_response == False)
        .group_by(DnsEvent.query_name)
        .order_by(func.count(DnsEvent.id).desc())
        .limit(10)
    )
    top_domains = [{'domain': d, 'count': c} for d, c in top_domains_result.all()]
    
    # 协议分布
    proto_result = await db.execute(
        select(Flow.protocol, func.count(Flow.id))
        .group_by(Flow.protocol)
    )
    proto_map = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}
    protocol_distribution = {
        proto_map.get(p, f'Other({p})'): c 
        for p, c in proto_result.all()
    }
    
    return {
        'total_datasets': total_datasets,
        'total_flows': total_flows,
        'total_bytes': int(total_bytes),
        'total_alerts': total_alerts,
        'open_alerts': open_alerts,
        'alerts_by_severity': alerts_by_severity,
        'alerts_by_type': alerts_by_type,
        'top_src_ips': top_src_ips,
        'top_dst_ips': top_dst_ips,
        'top_domains': top_domains,
        'protocol_distribution': protocol_distribution
    }


@router.get("/timeline")
async def get_traffic_timeline(
    dataset_id: Optional[str] = None,
    interval: int = Query(60, description="时间间隔（秒）"),
    db: AsyncSession = Depends(get_db)
):
    """获取流量时间线"""
    query = select(Flow.ts_start, Flow.bytes_up, Flow.bytes_down)
    
    if dataset_id:
        query = query.where(Flow.dataset_id == dataset_id)
    
    query = query.order_by(Flow.ts_start)
    
    result = await db.execute(query)
    flows = result.all()
    
    if not flows:
        return {'timeline': []}
    
    # 按时间桶聚合
    timeline = {}
    for ts_start, bytes_up, bytes_down in flows:
        if ts_start:
            bucket = ts_start.replace(second=0, microsecond=0)
            if bucket not in timeline:
                timeline[bucket] = {'bytes': 0, 'connections': 0}
            timeline[bucket]['bytes'] += (bytes_up or 0) + (bytes_down or 0)
            timeline[bucket]['connections'] += 1
    
    # 转换为列表
    timeline_list = [
        {
            'timestamp': ts.isoformat(),
            'bytes': data['bytes'],
            'connections': data['connections']
        }
        for ts, data in sorted(timeline.items())
    ]
    
    return {'timeline': timeline_list}


@router.get("/recent-alerts")
async def get_recent_alerts(
    limit: int = Query(10, ge=1, le=50),
    db: AsyncSession = Depends(get_db)
):
    """获取最近的告警"""
    result = await db.execute(
        select(Alert)
        .order_by(Alert.created_at.desc())
        .limit(limit)
    )
    alerts = result.scalars().all()
    
    return {
        'alerts': [
            {
                'id': a.id,
                'alert_type': a.alert_type.value if a.alert_type else 'unknown',
                'severity': a.severity.value if a.severity else 'unknown',
                'status': a.status.value if a.status else 'unknown',
                'title': a.title,
                'src_ip': a.src_ip,
                'score': a.score,
                'created_at': a.created_at.isoformat() if a.created_at else None
            }
            for a in alerts
        ]
    }


# 导出路由
export_router = APIRouter(prefix="/export", tags=["数据导出"])


@export_router.get("/flows/{dataset_id}/csv")
async def export_flows_csv(
    dataset_id: str,
    db: AsyncSession = Depends(get_db)
):
    """导出流数据为CSV"""
    csv_data = await export_service.export_flows_csv(db, dataset_id)
    
    return StreamingResponse(
        io.StringIO(csv_data),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=flows_{dataset_id}.csv"}
    )


@export_router.get("/flows/{dataset_id}/json")
async def export_flows_json(
    dataset_id: str,
    db: AsyncSession = Depends(get_db)
):
    """导出流数据为JSON"""
    json_data = await export_service.export_flows_json(db, dataset_id)
    
    return StreamingResponse(
        io.StringIO(json_data),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=flows_{dataset_id}.json"}
    )


@export_router.get("/alerts/{dataset_id}/csv")
async def export_alerts_csv(
    dataset_id: str,
    db: AsyncSession = Depends(get_db)
):
    """导出告警为CSV"""
    csv_data = await export_service.export_alerts_csv(db, dataset_id)
    
    return StreamingResponse(
        io.StringIO(csv_data),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=alerts_{dataset_id}.csv"}
    )


@export_router.get("/dns/{dataset_id}/csv")
async def export_dns_csv(
    dataset_id: str,
    db: AsyncSession = Depends(get_db)
):
    """导出DNS事件为CSV"""
    csv_data = await export_service.export_dns_csv(db, dataset_id)
    
    return StreamingResponse(
        io.StringIO(csv_data),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=dns_{dataset_id}.csv"}
    )


@export_router.get("/report/{dataset_id}/html")
async def export_html_report(
    dataset_id: str,
    db: AsyncSession = Depends(get_db)
):
    """生成HTML报告"""
    html_data = await export_service.generate_html_report(db, dataset_id)
    
    return StreamingResponse(
        io.StringIO(html_data),
        media_type="text/html",
        headers={"Content-Disposition": f"attachment; filename=report_{dataset_id}.html"}
    )
