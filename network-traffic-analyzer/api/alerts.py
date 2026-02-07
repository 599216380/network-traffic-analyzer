"""
告警管理API
"""
from typing import Optional, List
from datetime import datetime

from fastapi import APIRouter, HTTPException, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, update

from models import (
    Alert, AlertType, AlertSeverity, AlertStatus,
    AlertResponse, AlertListResponse, AlertQuery, AlertUpdate,
    get_db
)

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=AlertListResponse)
async def list_alerts(
    dataset_id: Optional[str] = None,
    alert_type: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    src_ip: Optional[str] = None,
    time_from: Optional[datetime] = None,
    time_to: Optional[datetime] = None,
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db)
):
    """查询告警列表"""
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
    
    if conditions:
        query = query.where(and_(*conditions))
        count_query = count_query.where(and_(*conditions))
    
    total_result = await db.execute(count_query)
    total = total_result.scalar()
    
    # 按严重程度和时间排序
    query = query.order_by(
        Alert.severity.desc(),
        Alert.created_at.desc()
    ).offset(offset).limit(limit)
    
    result = await db.execute(query)
    alerts = result.scalars().all()
    
    return AlertListResponse(
        total=total,
        items=[AlertResponse.model_validate(a) for a in alerts]
    )


@router.get("/summary")
async def get_alerts_summary(
    dataset_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """获取告警摘要统计"""
    base_condition = []
    if dataset_id:
        base_condition.append(Alert.dataset_id == dataset_id)
    
    # 按严重程度统计
    severity_query = select(
        Alert.severity, 
        func.count(Alert.id)
    ).group_by(Alert.severity)
    
    if base_condition:
        severity_query = severity_query.where(and_(*base_condition))
    
    severity_result = await db.execute(severity_query)
    by_severity = {
        row[0].value if row[0] else 'unknown': row[1] 
        for row in severity_result.all()
    }
    
    # 按类型统计
    type_query = select(
        Alert.alert_type,
        func.count(Alert.id)
    ).group_by(Alert.alert_type)
    
    if base_condition:
        type_query = type_query.where(and_(*base_condition))
    
    type_result = await db.execute(type_query)
    by_type = {
        row[0].value if row[0] else 'unknown': row[1]
        for row in type_result.all()
    }
    
    # 按状态统计
    status_query = select(
        Alert.status,
        func.count(Alert.id)
    ).group_by(Alert.status)
    
    if base_condition:
        status_query = status_query.where(and_(*base_condition))
    
    status_result = await db.execute(status_query)
    by_status = {
        row[0].value if row[0] else 'unknown': row[1]
        for row in status_result.all()
    }
    
    # 总数
    total_query = select(func.count(Alert.id))
    if base_condition:
        total_query = total_query.where(and_(*base_condition))
    
    total_result = await db.execute(total_query)
    total = total_result.scalar()
    
    return {
        "total": total,
        "by_severity": by_severity,
        "by_type": by_type,
        "by_status": by_status
    }


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(alert_id: int, db: AsyncSession = Depends(get_db)):
    """获取告警详情"""
    result = await db.execute(
        select(Alert).where(Alert.id == alert_id)
    )
    alert = result.scalar_one_or_none()
    
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    return AlertResponse.model_validate(alert)


@router.patch("/{alert_id}", response_model=AlertResponse)
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
        raise HTTPException(status_code=404, detail="Alert not found")
    
    # 更新字段
    update_dict = update_data.model_dump(exclude_unset=True)
    
    for key, value in update_dict.items():
        if value is not None:
            setattr(alert, key, value)
    
    if update_data.status:
        alert.handled_at = datetime.now()
    
    await db.commit()
    await db.refresh(alert)
    
    return AlertResponse.model_validate(alert)


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
        raise HTTPException(status_code=404, detail="Alert not found")
    
    alert.status = AlertStatus.CLOSED
    alert.handled_at = datetime.now()
    if notes:
        alert.notes = notes
    
    await db.commit()
    
    return {"message": "Alert closed successfully"}


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
        raise HTTPException(status_code=404, detail="Alert not found")
    
    alert.status = AlertStatus.FALSE_POSITIVE
    alert.handled_at = datetime.now()
    if notes:
        alert.notes = notes
    
    await db.commit()
    
    return {"message": "Alert marked as false positive"}


@router.delete("/{alert_id}")
async def delete_alert(alert_id: int, db: AsyncSession = Depends(get_db)):
    """删除告警"""
    result = await db.execute(
        select(Alert).where(Alert.id == alert_id)
    )
    alert = result.scalar_one_or_none()
    
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    await db.delete(alert)
    await db.commit()
    
    return {"message": "Alert deleted successfully"}
