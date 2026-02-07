"""
告警API路由
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, update
from typing import Optional, List
from datetime import datetime

from models import get_db, Alert, Flow, DnsEvent, HttpEvent
from models.database import AlertType, AlertSeverity, AlertStatus
from models.schemas import (
    AlertResponse, AlertListResponse, AlertQuery, AlertUpdate,
    FlowListResponse, DnsEventListResponse, HttpEventListResponse
)

router = APIRouter(prefix="/alerts", tags=["告警管理"])


@router.get("", response_model=AlertListResponse)
async def list_alerts(
    dataset_id: Optional[str] = None,
    alert_type: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    src_ip: Optional[str] = None,
    time_from: Optional[datetime] = None,
    time_to: Optional[datetime] = None,
    min_score: Optional[float] = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db)
):
    """
    获取告警列表
    
    支持多种过滤条件
    """
    query = select(Alert)
    count_query = select(func.count(Alert.id))
    
    conditions = []
    
    if dataset_id:
        conditions.append(Alert.dataset_id == dataset_id)
    if alert_type:
        conditions.append(Alert.alert_type == alert_type)
    if severity:
        conditions.append(Alert.severity == severity)
    if status:
        conditions.append(Alert.status == status)
    if src_ip:
        conditions.append(Alert.src_ip == src_ip)
    if time_from:
        conditions.append(Alert.ts_start >= time_from)
    if time_to:
        conditions.append(Alert.ts_end <= time_to)
    if min_score:
        conditions.append(Alert.score >= min_score)
    
    if conditions:
        query = query.where(and_(*conditions))
        count_query = count_query.where(and_(*conditions))
    
    # 获取总数
    count_result = await db.execute(count_query)
    total = count_result.scalar()
    
    # 排序：严重程度降序，时间降序
    query = query.order_by(
        Alert.severity.desc(),
        Alert.created_at.desc()
    ).offset(offset).limit(limit)
    
    result = await db.execute(query)
    alerts = result.scalars().all()
    
    return AlertListResponse(total=total, items=alerts)


@router.get("/summary")
async def get_alerts_summary(
    dataset_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """获取告警统计摘要"""
    base_query = select(Alert)
    if dataset_id:
        base_query = base_query.where(Alert.dataset_id == dataset_id)
    
    # 按严重程度统计
    severity_query = select(
        Alert.severity, 
        func.count(Alert.id)
    ).group_by(Alert.severity)
    if dataset_id:
        severity_query = severity_query.where(Alert.dataset_id == dataset_id)
    
    severity_result = await db.execute(severity_query)
    by_severity = {
        str(s.value) if s else 'unknown': c 
        for s, c in severity_result.all()
    }
    
    # 按类型统计
    type_query = select(
        Alert.alert_type,
        func.count(Alert.id)
    ).group_by(Alert.alert_type)
    if dataset_id:
        type_query = type_query.where(Alert.dataset_id == dataset_id)
    
    type_result = await db.execute(type_query)
    by_type = {
        str(t.value) if t else 'unknown': c 
        for t, c in type_result.all()
    }
    
    # 按状态统计
    status_query = select(
        Alert.status,
        func.count(Alert.id)
    ).group_by(Alert.status)
    if dataset_id:
        status_query = status_query.where(Alert.dataset_id == dataset_id)
    
    status_result = await db.execute(status_query)
    by_status = {
        str(s.value) if s else 'unknown': c 
        for s, c in status_result.all()
    }
    
    # 总数
    count_query = select(func.count(Alert.id))
    if dataset_id:
        count_query = count_query.where(Alert.dataset_id == dataset_id)
    total_result = await db.execute(count_query)
    total = total_result.scalar()
    
    return {
        'total': total,
        'by_severity': by_severity,
        'by_type': by_type,
        'by_status': by_status
    }


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(alert_id: int, db: AsyncSession = Depends(get_db)):
    """获取告警详情"""
    result = await db.execute(
        select(Alert).where(Alert.id == alert_id)
    )
    alert = result.scalar_one_or_none()
    
    if not alert:
        raise HTTPException(status_code=404, detail="告警不存在")
    
    return alert


@router.put("/{alert_id}", response_model=AlertResponse)
async def update_alert(
    alert_id: int,
    update_data: AlertUpdate,
    db: AsyncSession = Depends(get_db)
):
    """更新告警状态"""
    result = await db.execute(
        select(Alert).where(Alert.id == alert_id)
    )
    alert = result.scalar_one_or_none()
    
    if not alert:
        raise HTTPException(status_code=404, detail="告警不存在")
    
    # 更新字段
    if update_data.status:
        alert.status = update_data.status
    if update_data.severity:
        alert.severity = update_data.severity
    if update_data.tags is not None:
        alert.tags = update_data.tags
    if update_data.notes is not None:
        alert.notes = update_data.notes
    
    await db.commit()
    await db.refresh(alert)
    
    return alert


@router.post("/{alert_id}/close")
async def close_alert(
    alert_id: int,
    notes: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """关闭告警"""
    result = await db.execute(
        select(Alert).where(Alert.id == alert_id)
    )
    alert = result.scalar_one_or_none()
    
    if not alert:
        raise HTTPException(status_code=404, detail="告警不存在")
    
    alert.status = AlertStatus.CLOSED
    alert.handled_at = datetime.now()
    if notes:
        alert.notes = notes
    
    await db.commit()
    
    return {"message": "告警已关闭"}


@router.post("/{alert_id}/false-positive")
async def mark_false_positive(
    alert_id: int,
    notes: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """标记为误报"""
    result = await db.execute(
        select(Alert).where(Alert.id == alert_id)
    )
    alert = result.scalar_one_or_none()
    
    if not alert:
        raise HTTPException(status_code=404, detail="告警不存在")
    
    alert.status = AlertStatus.FALSE_POSITIVE
    alert.handled_at = datetime.now()
    if notes:
        alert.notes = notes
    
    await db.commit()
    
    return {"message": "已标记为误报"}


@router.get("/{alert_id}/related-flows", response_model=FlowListResponse)
async def get_alert_related_flows(
    alert_id: int,
    db: AsyncSession = Depends(get_db)
):
    """获取告警关联的流"""
    result = await db.execute(
        select(Alert).where(Alert.id == alert_id)
    )
    alert = result.scalar_one_or_none()
    
    if not alert:
        raise HTTPException(status_code=404, detail="告警不存在")
    
    flows = []
    
    if alert.related_flow_ids:
        flow_result = await db.execute(
            select(Flow).where(Flow.id.in_(alert.related_flow_ids))
        )
        flows = flow_result.scalars().all()
    
    return FlowListResponse(total=len(flows), items=flows)


@router.get("/{alert_id}/related-dns", response_model=DnsEventListResponse)
async def get_alert_related_dns(
    alert_id: int,
    db: AsyncSession = Depends(get_db)
):
    """获取告警关联的DNS事件"""
    result = await db.execute(
        select(Alert).where(Alert.id == alert_id)
    )
    alert = result.scalar_one_or_none()
    
    if not alert:
        raise HTTPException(status_code=404, detail="告警不存在")
    
    events = []
    
    if alert.related_dns_ids:
        dns_result = await db.execute(
            select(DnsEvent).where(DnsEvent.id.in_(alert.related_dns_ids))
        )
        events = dns_result.scalars().all()
    
    return DnsEventListResponse(total=len(events), items=events)


@router.post("/batch-close")
async def batch_close_alerts(
    alert_ids: List[int],
    notes: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """批量关闭告警"""
    await db.execute(
        update(Alert)
        .where(Alert.id.in_(alert_ids))
        .values(
            status=AlertStatus.CLOSED,
            handled_at=datetime.now(),
            notes=notes
        )
    )
    await db.commit()
    
    return {"message": f"已关闭 {len(alert_ids)} 个告警"}
