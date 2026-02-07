"""
流量查询API路由
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_
from typing import Optional, List
from datetime import datetime

from models import get_db, Flow, DnsEvent, HttpEvent, TlsEvent
from models.schemas import (
    FlowResponse, FlowListResponse, FlowQuery,
    DnsEventResponse, DnsEventListResponse, DnsQuery,
    HttpEventResponse, HttpEventListResponse,
    TlsEventResponse, TlsEventListResponse
)

router = APIRouter(prefix="/flows", tags=["流量查询"])


@router.get("", response_model=FlowListResponse)
async def query_flows(
    dataset_id: Optional[str] = None,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
    protocol: Optional[int] = None,
    app_protocol: Optional[str] = None,
    state: Optional[str] = None,
    time_from: Optional[datetime] = None,
    time_to: Optional[datetime] = None,
    min_bytes: Optional[int] = None,
    max_bytes: Optional[int] = None,
    order_by: str = Query("ts_start", regex="^(ts_start|ts_end|bytes_up|bytes_down|duration)$"),
    order_desc: bool = True,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db)
):
    """
    查询流量记录
    
    支持多种过滤条件和排序
    """
    # 构建查询
    query = select(Flow)
    count_query = select(func.count(Flow.id))
    
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
    if state:
        conditions.append(Flow.state == state)
    if time_from:
        conditions.append(Flow.ts_start >= time_from)
    if time_to:
        conditions.append(Flow.ts_end <= time_to)
    if min_bytes:
        conditions.append((Flow.bytes_up + Flow.bytes_down) >= min_bytes)
    if max_bytes:
        conditions.append((Flow.bytes_up + Flow.bytes_down) <= max_bytes)
    
    if conditions:
        query = query.where(and_(*conditions))
        count_query = count_query.where(and_(*conditions))
    
    # 获取总数
    count_result = await db.execute(count_query)
    total = count_result.scalar()
    
    # 排序
    order_column = getattr(Flow, order_by)
    if order_desc:
        query = query.order_by(order_column.desc())
    else:
        query = query.order_by(order_column.asc())
    
    # 分页
    query = query.offset(offset).limit(limit)
    
    result = await db.execute(query)
    flows = result.scalars().all()
    
    return FlowListResponse(total=total, items=flows)


@router.get("/{flow_id}", response_model=FlowResponse)
async def get_flow(flow_id: int, db: AsyncSession = Depends(get_db)):
    """获取流详情"""
    result = await db.execute(
        select(Flow).where(Flow.id == flow_id)
    )
    flow = result.scalar_one_or_none()
    
    if not flow:
        raise HTTPException(status_code=404, detail="流记录不存在")
    
    return flow


@router.get("/{flow_id}/related-dns", response_model=DnsEventListResponse)
async def get_flow_dns(flow_id: int, db: AsyncSession = Depends(get_db)):
    """获取流相关的DNS事件"""
    # 获取flow
    flow_result = await db.execute(
        select(Flow).where(Flow.id == flow_id)
    )
    flow = flow_result.scalar_one_or_none()
    
    if not flow:
        raise HTTPException(status_code=404, detail="流记录不存在")
    
    # 查询相关DNS（按IP和时间范围）
    result = await db.execute(
        select(DnsEvent).where(
            and_(
                DnsEvent.dataset_id == flow.dataset_id,
                or_(
                    DnsEvent.src_ip == flow.src_ip,
                    DnsEvent.src_ip == flow.dst_ip
                ),
                DnsEvent.timestamp >= flow.ts_start,
                DnsEvent.timestamp <= flow.ts_end
            )
        )
    )
    events = result.scalars().all()
    
    return DnsEventListResponse(total=len(events), items=events)


@router.get("/{flow_id}/related-http", response_model=HttpEventListResponse)
async def get_flow_http(flow_id: int, db: AsyncSession = Depends(get_db)):
    """获取流相关的HTTP事件"""
    flow_result = await db.execute(
        select(Flow).where(Flow.id == flow_id)
    )
    flow = flow_result.scalar_one_or_none()
    
    if not flow:
        raise HTTPException(status_code=404, detail="流记录不存在")
    
    result = await db.execute(
        select(HttpEvent).where(
            and_(
                HttpEvent.dataset_id == flow.dataset_id,
                HttpEvent.src_ip == flow.src_ip,
                HttpEvent.dst_ip == flow.dst_ip,
                HttpEvent.src_port == flow.src_port,
                HttpEvent.dst_port == flow.dst_port
            )
        )
    )
    events = result.scalars().all()
    
    return HttpEventListResponse(total=len(events), items=events)


# DNS查询路由
dns_router = APIRouter(prefix="/dns", tags=["DNS事件"])


@dns_router.get("", response_model=DnsEventListResponse)
async def query_dns(
    dataset_id: Optional[str] = None,
    src_ip: Optional[str] = None,
    query_name: Optional[str] = None,
    query_type: Optional[str] = None,
    response_code: Optional[str] = None,
    time_from: Optional[datetime] = None,
    time_to: Optional[datetime] = None,
    min_entropy: Optional[float] = None,
    is_response: Optional[bool] = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
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
    if is_response is not None:
        conditions.append(DnsEvent.is_response == is_response)
    
    if conditions:
        query = query.where(and_(*conditions))
        count_query = count_query.where(and_(*conditions))
    
    count_result = await db.execute(count_query)
    total = count_result.scalar()
    
    query = query.order_by(DnsEvent.timestamp.desc()).offset(offset).limit(limit)
    
    result = await db.execute(query)
    events = result.scalars().all()
    
    return DnsEventListResponse(total=total, items=events)


@dns_router.get("/suspicious")
async def get_suspicious_dns(
    dataset_id: str,
    min_entropy: float = Query(3.5),
    min_length: int = Query(50),
    limit: int = Query(100),
    db: AsyncSession = Depends(get_db)
):
    """获取可疑DNS查询（高熵值/长域名）"""
    result = await db.execute(
        select(DnsEvent).where(
            and_(
                DnsEvent.dataset_id == dataset_id,
                or_(
                    DnsEvent.entropy >= min_entropy,
                    DnsEvent.qname_length >= min_length
                )
            )
        ).order_by(DnsEvent.entropy.desc()).limit(limit)
    )
    events = result.scalars().all()
    
    return DnsEventListResponse(total=len(events), items=events)


# HTTP查询路由
http_router = APIRouter(prefix="/http", tags=["HTTP事件"])


@http_router.get("", response_model=HttpEventListResponse)
async def query_http(
    dataset_id: Optional[str] = None,
    src_ip: Optional[str] = None,
    host: Optional[str] = None,
    method: Optional[str] = None,
    status_code: Optional[int] = None,
    uri: Optional[str] = None,
    time_from: Optional[datetime] = None,
    time_to: Optional[datetime] = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
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
    
    count_result = await db.execute(count_query)
    total = count_result.scalar()
    
    query = query.order_by(HttpEvent.timestamp.desc()).offset(offset).limit(limit)
    
    result = await db.execute(query)
    events = result.scalars().all()
    
    return HttpEventListResponse(total=total, items=events)


# TLS查询路由
tls_router = APIRouter(prefix="/tls", tags=["TLS事件"])


@tls_router.get("", response_model=TlsEventListResponse)
async def query_tls(
    dataset_id: Optional[str] = None,
    sni: Optional[str] = None,
    ja3_hash: Optional[str] = None,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db)
):
    """查询TLS事件"""
    query = select(TlsEvent)
    count_query = select(func.count(TlsEvent.id))
    
    conditions = []
    
    if dataset_id:
        conditions.append(TlsEvent.dataset_id == dataset_id)
    if sni:
        conditions.append(TlsEvent.sni.contains(sni))
    if ja3_hash:
        conditions.append(TlsEvent.ja3_hash == ja3_hash)
    if src_ip:
        conditions.append(TlsEvent.src_ip == src_ip)
    if dst_ip:
        conditions.append(TlsEvent.dst_ip == dst_ip)
    
    if conditions:
        query = query.where(and_(*conditions))
        count_query = count_query.where(and_(*conditions))
    
    count_result = await db.execute(count_query)
    total = count_result.scalar()
    
    query = query.order_by(TlsEvent.timestamp.desc()).offset(offset).limit(limit)
    
    result = await db.execute(query)
    events = result.scalars().all()
    
    return TlsEventListResponse(total=total, items=events)
