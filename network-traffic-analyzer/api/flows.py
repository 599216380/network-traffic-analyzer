"""
流量数据查询API
"""
from typing import Optional, List
from datetime import datetime

from fastapi import APIRouter, HTTPException, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_

from models import (
    Flow, DnsEvent, HttpEvent, TlsEvent, Dataset,
    FlowResponse, FlowListResponse, FlowQuery,
    DnsEventResponse, DnsEventListResponse, DnsQuery,
    HttpEventResponse, HttpEventListResponse,
    TlsEventResponse, TlsEventListResponse,
    get_db
)

router = APIRouter(prefix="/flows", tags=["flows"])


@router.get("", response_model=FlowListResponse)
async def list_flows(
    dataset_id: Optional[str] = None,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
    protocol: Optional[int] = None,
    app_protocol: Optional[str] = None,
    time_from: Optional[datetime] = None,
    time_to: Optional[datetime] = None,
    min_bytes: Optional[int] = None,
    state: Optional[str] = None,
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0, ge=0),
    order_by: str = "ts_start",
    order_desc: bool = True,
    db: AsyncSession = Depends(get_db)
):
    """查询流量数据"""
    query = select(Flow)
    count_query = select(func.count(Flow.id))
    
    # 构建过滤条件
    conditions = []
    
    if dataset_id:
        conditions.append(Flow.dataset_id == dataset_id)
    if src_ip:
        conditions.append(Flow.src_ip == src_ip)
    if dst_ip:
        conditions.append(Flow.dst_ip == dst_ip)
    if src_port:
        conditions.append(Flow.src_port == src_port)
    if dst_port:
        conditions.append(Flow.dst_port == dst_port)
    if protocol:
        conditions.append(Flow.protocol == protocol)
    if app_protocol:
        conditions.append(Flow.app_protocol == app_protocol)
    if time_from:
        conditions.append(Flow.ts_start >= time_from)
    if time_to:
        conditions.append(Flow.ts_end <= time_to)
    if min_bytes:
        conditions.append((Flow.bytes_up + Flow.bytes_down) >= min_bytes)
    if state:
        conditions.append(Flow.state == state)
    
    if conditions:
        query = query.where(and_(*conditions))
        count_query = count_query.where(and_(*conditions))
    
    # 总数
    total_result = await db.execute(count_query)
    total = total_result.scalar()
    
    # 排序
    order_column = getattr(Flow, order_by, Flow.ts_start)
    if order_desc:
        query = query.order_by(order_column.desc())
    else:
        query = query.order_by(order_column.asc())
    
    # 分页
    query = query.offset(offset).limit(limit)
    
    result = await db.execute(query)
    flows = result.scalars().all()
    
    return FlowListResponse(
        total=total,
        items=[FlowResponse.model_validate(f) for f in flows]
    )


@router.get("/{flow_id}", response_model=FlowResponse)
async def get_flow(flow_id: int, db: AsyncSession = Depends(get_db)):
    """获取单个流详情"""
    result = await db.execute(
        select(Flow).where(Flow.id == flow_id)
    )
    flow = result.scalar_one_or_none()
    
    if not flow:
        raise HTTPException(status_code=404, detail="Flow not found")
    
    return FlowResponse.model_validate(flow)


@router.get("/{flow_id}/related")
async def get_related_events(flow_id: int, db: AsyncSession = Depends(get_db)):
    """获取流相关的应用层事件"""
    # 获取流
    result = await db.execute(
        select(Flow).where(Flow.id == flow_id)
    )
    flow = result.scalar_one_or_none()
    
    if not flow:
        raise HTTPException(status_code=404, detail="Flow not found")
    
    # 查询相关DNS事件
    dns_result = await db.execute(
        select(DnsEvent).where(
            and_(
                DnsEvent.dataset_id == flow.dataset_id,
                or_(
                    and_(DnsEvent.src_ip == flow.src_ip, DnsEvent.dst_ip == flow.dst_ip),
                    and_(DnsEvent.src_ip == flow.dst_ip, DnsEvent.dst_ip == flow.src_ip)
                ),
                DnsEvent.timestamp >= flow.ts_start,
                DnsEvent.timestamp <= flow.ts_end
            )
        ).limit(50)
    )
    dns_events = dns_result.scalars().all()
    
    # 查询相关HTTP事件
    http_result = await db.execute(
        select(HttpEvent).where(
            and_(
                HttpEvent.dataset_id == flow.dataset_id,
                HttpEvent.src_ip == flow.src_ip,
                HttpEvent.dst_ip == flow.dst_ip,
                HttpEvent.src_port == flow.src_port,
                HttpEvent.dst_port == flow.dst_port
            )
        ).limit(50)
    )
    http_events = http_result.scalars().all()
    
    # 查询相关TLS事件
    tls_result = await db.execute(
        select(TlsEvent).where(
            and_(
                TlsEvent.dataset_id == flow.dataset_id,
                TlsEvent.src_ip == flow.src_ip,
                TlsEvent.dst_ip == flow.dst_ip,
                TlsEvent.src_port == flow.src_port,
                TlsEvent.dst_port == flow.dst_port
            )
        ).limit(50)
    )
    tls_events = tls_result.scalars().all()
    
    return {
        "flow": FlowResponse.model_validate(flow),
        "dns_events": [DnsEventResponse.model_validate(e) for e in dns_events],
        "http_events": [HttpEventResponse.model_validate(e) for e in http_events],
        "tls_events": [TlsEventResponse.model_validate(e) for e in tls_events]
    }


# DNS Events Router
dns_router = APIRouter(prefix="/dns", tags=["dns"])


@dns_router.get("", response_model=DnsEventListResponse)
async def list_dns_events(
    dataset_id: Optional[str] = None,
    src_ip: Optional[str] = None,
    query_name: Optional[str] = None,
    query_type: Optional[str] = None,
    response_code: Optional[str] = None,
    time_from: Optional[datetime] = None,
    time_to: Optional[datetime] = None,
    min_entropy: Optional[float] = None,
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db)
):
    """查询DNS事件"""
    query = select(DnsEvent)
    count_query = select(func.count(DnsEvent.id))
    
    conditions = []
    
    if dataset_id:
        conditions.append(DnsEvent.dataset_id == dataset_id)
    if src_ip:
        conditions.append(DnsEvent.src_ip == src_ip)
    if query_name:
        conditions.append(DnsEvent.query_name.contains(query_name))
    if query_type:
        conditions.append(DnsEvent.query_type == query_type)
    if response_code:
        conditions.append(DnsEvent.response_code == response_code)
    if time_from:
        conditions.append(DnsEvent.timestamp >= time_from)
    if time_to:
        conditions.append(DnsEvent.timestamp <= time_to)
    if min_entropy:
        conditions.append(DnsEvent.entropy >= min_entropy)
    
    if conditions:
        query = query.where(and_(*conditions))
        count_query = count_query.where(and_(*conditions))
    
    total_result = await db.execute(count_query)
    total = total_result.scalar()
    
    query = query.order_by(DnsEvent.timestamp.desc()).offset(offset).limit(limit)
    
    result = await db.execute(query)
    events = result.scalars().all()
    
    return DnsEventListResponse(
        total=total,
        items=[DnsEventResponse.model_validate(e) for e in events]
    )


# HTTP Events Router  
http_router = APIRouter(prefix="/http", tags=["http"])


@http_router.get("", response_model=HttpEventListResponse)
async def list_http_events(
    dataset_id: Optional[str] = None,
    src_ip: Optional[str] = None,
    host: Optional[str] = None,
    method: Optional[str] = None,
    status_code: Optional[int] = None,
    uri: Optional[str] = None,
    time_from: Optional[datetime] = None,
    time_to: Optional[datetime] = None,
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db)
):
    """查询HTTP事件"""
    query = select(HttpEvent)
    count_query = select(func.count(HttpEvent.id))
    
    conditions = []
    
    if dataset_id:
        conditions.append(HttpEvent.dataset_id == dataset_id)
    if src_ip:
        conditions.append(HttpEvent.src_ip == src_ip)
    if host:
        conditions.append(HttpEvent.host.contains(host))
    if method:
        conditions.append(HttpEvent.method == method)
    if status_code:
        conditions.append(HttpEvent.status_code == status_code)
    if uri:
        conditions.append(HttpEvent.uri.contains(uri))
    if time_from:
        conditions.append(HttpEvent.timestamp >= time_from)
    if time_to:
        conditions.append(HttpEvent.timestamp <= time_to)
    
    if conditions:
        query = query.where(and_(*conditions))
        count_query = count_query.where(and_(*conditions))
    
    total_result = await db.execute(count_query)
    total = total_result.scalar()
    
    query = query.order_by(HttpEvent.timestamp.desc()).offset(offset).limit(limit)
    
    result = await db.execute(query)
    events = result.scalars().all()
    
    return HttpEventListResponse(
        total=total,
        items=[HttpEventResponse.model_validate(e) for e in events]
    )


# TLS Events Router
tls_router = APIRouter(prefix="/tls", tags=["tls"])


@tls_router.get("", response_model=TlsEventListResponse)
async def list_tls_events(
    dataset_id: Optional[str] = None,
    src_ip: Optional[str] = None,
    sni: Optional[str] = None,
    ja3_hash: Optional[str] = None,
    time_from: Optional[datetime] = None,
    time_to: Optional[datetime] = None,
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db)
):
    """查询TLS事件"""
    query = select(TlsEvent)
    count_query = select(func.count(TlsEvent.id))
    
    conditions = []
    
    if dataset_id:
        conditions.append(TlsEvent.dataset_id == dataset_id)
    if src_ip:
        conditions.append(TlsEvent.src_ip == src_ip)
    if sni:
        conditions.append(TlsEvent.sni.contains(sni))
    if ja3_hash:
        conditions.append(TlsEvent.ja3_hash == ja3_hash)
    if time_from:
        conditions.append(TlsEvent.timestamp >= time_from)
    if time_to:
        conditions.append(TlsEvent.timestamp <= time_to)
    
    if conditions:
        query = query.where(and_(*conditions))
        count_query = count_query.where(and_(*conditions))
    
    total_result = await db.execute(count_query)
    total = total_result.scalar()
    
    query = query.order_by(TlsEvent.timestamp.desc()).offset(offset).limit(limit)
    
    result = await db.execute(query)
    events = result.scalars().all()
    
    return TlsEventListResponse(
        total=total,
        items=[TlsEventResponse.model_validate(e) for e in events]
    )
