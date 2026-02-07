"""
数据集API路由
"""
import os
import shutil
import uuid
import asyncio
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, BackgroundTasks, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, delete
from typing import Optional, List

from models import get_db, Dataset, Flow, DnsEvent, HttpEvent, TlsEvent, Alert
from models.schemas import DatasetResponse, DatasetListResponse, DatasetStats
from services.import_service import import_service
from config.settings import get_settings

settings = get_settings()
router = APIRouter(prefix="/datasets", tags=["数据集"])


@router.get("", response_model=DatasetListResponse)
async def list_datasets(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db)
):
    """获取数据集列表"""
    # 获取总数
    count_result = await db.execute(select(func.count(Dataset.id)))
    total = count_result.scalar()
    
    # 获取列表
    result = await db.execute(
        select(Dataset)
        .order_by(Dataset.created_at.desc())
        .offset(skip)
        .limit(limit)
    )
    datasets = result.scalars().all()
    
    return DatasetListResponse(total=total, items=datasets)


@router.get("/{dataset_id}", response_model=DatasetResponse)
async def get_dataset(dataset_id: str, db: AsyncSession = Depends(get_db)):
    """获取数据集详情"""
    result = await db.execute(
        select(Dataset).where(Dataset.id == dataset_id)
    )
    dataset = result.scalar_one_or_none()
    
    if not dataset:
        raise HTTPException(status_code=404, detail="数据集不存在")
    
    return dataset


@router.post("/import", response_model=DatasetResponse)
async def import_pcap(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    name: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    导入PCAP文件
    
    上传pcap/pcapng文件，后台解析并入库
    """
    # 验证文件扩展名
    file_ext = os.path.splitext(file.filename)[1].lower()
    if file_ext not in settings.ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"不支持的文件格式，支持: {settings.ALLOWED_EXTENSIONS}"
        )
    
    # 验证文件大小
    file.file.seek(0, 2)
    file_size = file.file.tell()
    file.file.seek(0)
    
    if file_size > settings.MAX_UPLOAD_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"文件过大，最大支持 {settings.MAX_UPLOAD_SIZE / 1024 / 1024:.0f}MB"
        )
    
    # 生成唯一ID和保存路径
    dataset_id = str(uuid.uuid4())
    save_dir = settings.DATASETS_DIR / dataset_id
    save_dir.mkdir(parents=True, exist_ok=True)
    
    filepath = save_dir / f"raw{file_ext}"
    
    # 保存文件
    try:
        with open(filepath, "wb") as f:
            shutil.copyfileobj(file.file, f)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"文件保存失败: {str(e)}")
    
    # 创建导入任务
    await import_service.create_import_task(
        filename=file.filename,
        filepath=str(filepath),
        name=name or file.filename
    )
    
    # 更新数据集ID
    result = await db.execute(
        select(Dataset).order_by(Dataset.created_at.desc()).limit(1)
    )
    dataset = result.scalar_one()
    
    # 在后台执行解析
    background_tasks.add_task(import_service.process_import, dataset.id)
    
    return dataset


@router.delete("/{dataset_id}")
async def delete_dataset(dataset_id: str, db: AsyncSession = Depends(get_db)):
    """删除数据集"""
    result = await db.execute(
        select(Dataset).where(Dataset.id == dataset_id)
    )
    dataset = result.scalar_one_or_none()
    
    if not dataset:
        raise HTTPException(status_code=404, detail="数据集不存在")
    
    # 删除文件
    dataset_dir = settings.DATASETS_DIR / dataset_id
    if dataset_dir.exists():
        shutil.rmtree(dataset_dir)
    
    # 删除数据库记录（级联删除）
    await db.delete(dataset)
    await db.commit()
    
    return {"message": "数据集已删除"}


@router.get("/{dataset_id}/stats", response_model=DatasetStats)
async def get_dataset_stats(dataset_id: str, db: AsyncSession = Depends(get_db)):
    """获取数据集统计信息"""
    # 验证数据集存在
    result = await db.execute(
        select(Dataset).where(Dataset.id == dataset_id)
    )
    dataset = result.scalar_one_or_none()
    
    if not dataset:
        raise HTTPException(status_code=404, detail="数据集不存在")
    
    # 获取唯一IP数
    src_ips_result = await db.execute(
        select(func.count(func.distinct(Flow.src_ip)))
        .where(Flow.dataset_id == dataset_id)
    )
    unique_src_ips = src_ips_result.scalar() or 0
    
    dst_ips_result = await db.execute(
        select(func.count(func.distinct(Flow.dst_ip)))
        .where(Flow.dataset_id == dataset_id)
    )
    unique_dst_ips = dst_ips_result.scalar() or 0
    
    # 协议分布
    proto_result = await db.execute(
        select(Flow.protocol, func.count(Flow.id))
        .where(Flow.dataset_id == dataset_id)
        .group_by(Flow.protocol)
    )
    proto_map = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}
    protocol_distribution = {
        proto_map.get(proto, f'Other({proto})'): count 
        for proto, count in proto_result.all()
    }
    
    # Top talkers
    top_src_result = await db.execute(
        select(Flow.src_ip, func.sum(Flow.bytes_up + Flow.bytes_down).label('total_bytes'))
        .where(Flow.dataset_id == dataset_id)
        .group_by(Flow.src_ip)
        .order_by(func.sum(Flow.bytes_up + Flow.bytes_down).desc())
        .limit(10)
    )
    top_talkers = [{'ip': ip, 'bytes': bytes} for ip, bytes in top_src_result.all()]
    
    # Top ports
    top_ports_result = await db.execute(
        select(Flow.dst_port, func.count(Flow.id).label('count'))
        .where(Flow.dataset_id == dataset_id)
        .group_by(Flow.dst_port)
        .order_by(func.count(Flow.id).desc())
        .limit(10)
    )
    top_ports = [{'port': port, 'count': count} for port, count in top_ports_result.all()]
    
    return DatasetStats(
        total_packets=dataset.total_packets,
        total_bytes=dataset.total_bytes,
        total_flows=dataset.total_flows,
        unique_src_ips=unique_src_ips,
        unique_dst_ips=unique_dst_ips,
        protocol_distribution=protocol_distribution,
        top_talkers=top_talkers,
        top_ports=top_ports,
        time_range={
            'start': dataset.start_time,
            'end': dataset.end_time
        }
    )


@router.post("/{dataset_id}/reanalyze")
async def reanalyze_dataset(
    dataset_id: str,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
    """重新分析数据集（重新运行检测）"""
    result = await db.execute(
        select(Dataset).where(Dataset.id == dataset_id)
    )
    dataset = result.scalar_one_or_none()
    
    if not dataset:
        raise HTTPException(status_code=404, detail="数据集不存在")
    
    if dataset.status.value != 'done':
        raise HTTPException(status_code=400, detail="数据集尚未完成解析")
    
    # 清除现有告警
    await db.execute(
        delete(Alert).where(Alert.dataset_id == dataset_id)
    )
    await db.commit()
    
    # 后台重新分析
    async def rerun_detection():
        from models.db_session import get_db_context
        from detection import create_default_engine
        
        async with get_db_context() as session:
            # 获取flows
            flows_result = await session.execute(
                select(Flow).where(Flow.dataset_id == dataset_id)
            )
            flows = flows_result.scalars().all()
            
            # 获取DNS事件
            dns_result = await session.execute(
                select(DnsEvent).where(DnsEvent.dataset_id == dataset_id)
            )
            dns_events = dns_result.scalars().all()
            
            # 获取HTTP事件
            http_result = await session.execute(
                select(HttpEvent).where(HttpEvent.dataset_id == dataset_id)
            )
            http_events = http_result.scalars().all()
            
            # 运行检测
            engine = create_default_engine()
            results = engine.run_all(flows, dns_events, http_events)
            
            # 保存告警
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
                    rule_id=result.rule_id,
                    rule_name=result.rule_name
                )
                session.add(alert)
            
            await session.commit()
    
    background_tasks.add_task(rerun_detection)
    
    return {"message": "重新分析任务已提交"}
