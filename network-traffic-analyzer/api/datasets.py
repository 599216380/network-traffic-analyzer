"""
数据集管理API
"""
import os
import uuid
import shutil
import asyncio
from typing import Optional
from datetime import datetime

from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Depends, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, delete

from models import (
    Dataset, Flow, DnsEvent, HttpEvent, Alert, TaskStatus,
    DatasetResponse, DatasetListResponse, DatasetStats,
    get_db
)
from services.import_service import import_service
from config.settings import get_settings

settings = get_settings()
router = APIRouter(prefix="/datasets", tags=["datasets"])


@router.get("", response_model=DatasetListResponse)
async def list_datasets(
    skip: int = 0,
    limit: int = 20,
    status: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """获取数据集列表"""
    query = select(Dataset).order_by(Dataset.created_at.desc())
    
    if status:
        query = query.where(Dataset.status == status)
    
    # 总数
    count_query = select(func.count(Dataset.id))
    if status:
        count_query = count_query.where(Dataset.status == status)
    
    total_result = await db.execute(count_query)
    total = total_result.scalar()
    
    # 分页
    query = query.offset(skip).limit(limit)
    result = await db.execute(query)
    datasets = result.scalars().all()
    
    return DatasetListResponse(
        total=total,
        items=[DatasetResponse.model_validate(d) for d in datasets]
    )


@router.get("/{dataset_id}", response_model=DatasetResponse)
async def get_dataset(dataset_id: str, db: AsyncSession = Depends(get_db)):
    """获取数据集详情"""
    result = await db.execute(
        select(Dataset).where(Dataset.id == dataset_id)
    )
    dataset = result.scalar_one_or_none()
    
    if not dataset:
        raise HTTPException(status_code=404, detail="Dataset not found")
    
    return DatasetResponse.model_validate(dataset)


@router.post("/import", response_model=DatasetResponse)
async def import_pcap(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    name: Optional[str] = Form(None),
    db: AsyncSession = Depends(get_db)
):
    """上传并导入PCAP文件"""
    # 验证文件
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")
    
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in settings.ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400, 
            detail=f"Invalid file type. Allowed: {settings.ALLOWED_EXTENSIONS}"
        )
    
    # 检查文件大小
    file.file.seek(0, 2)
    file_size = file.file.tell()
    file.file.seek(0)
    
    if file_size > settings.MAX_UPLOAD_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"File too large. Max size: {settings.MAX_UPLOAD_SIZE / 1024 / 1024}MB"
        )
    
    # 保存文件
    dataset_id = str(uuid.uuid4())
    dataset_dir = settings.DATASETS_DIR / dataset_id
    dataset_dir.mkdir(parents=True, exist_ok=True)
    
    filepath = dataset_dir / f"raw{ext}"
    
    with open(filepath, "wb") as f:
        shutil.copyfileobj(file.file, f)
    
    # 创建导入任务
    task_id = await import_service.create_import_task(
        filename=file.filename,
        filepath=str(filepath),
        name=name or file.filename
    )
    
    # 后台执行导入
    background_tasks.add_task(import_service.process_import, task_id)
    
    # 返回数据集信息
    result = await db.execute(
        select(Dataset).where(Dataset.id == task_id)
    )
    dataset = result.scalar_one()
    
    return DatasetResponse.model_validate(dataset)


@router.get("/{dataset_id}/stats", response_model=DatasetStats)
async def get_dataset_stats(dataset_id: str, db: AsyncSession = Depends(get_db)):
    """获取数据集统计信息"""
    # 验证数据集存在
    result = await db.execute(
        select(Dataset).where(Dataset.id == dataset_id)
    )
    dataset = result.scalar_one_or_none()
    
    if not dataset:
        raise HTTPException(status_code=404, detail="Dataset not found")
    
    # 获取唯一IP数
    src_ips_result = await db.execute(
        select(func.count(func.distinct(Flow.src_ip))).where(Flow.dataset_id == dataset_id)
    )
    unique_src_ips = src_ips_result.scalar() or 0
    
    dst_ips_result = await db.execute(
        select(func.count(func.distinct(Flow.dst_ip))).where(Flow.dataset_id == dataset_id)
    )
    unique_dst_ips = dst_ips_result.scalar() or 0
    
    # 协议分布
    proto_result = await db.execute(
        select(Flow.protocol, func.count(Flow.id))
        .where(Flow.dataset_id == dataset_id)
        .group_by(Flow.protocol)
    )
    proto_rows = proto_result.all()
    
    proto_map = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}
    protocol_distribution = {
        proto_map.get(row[0], f'Other({row[0]})'): row[1] 
        for row in proto_rows
    }
    
    # Top talkers (by bytes)
    top_src_result = await db.execute(
        select(Flow.src_ip, func.sum(Flow.bytes_up + Flow.bytes_down).label('total_bytes'))
        .where(Flow.dataset_id == dataset_id)
        .group_by(Flow.src_ip)
        .order_by(func.sum(Flow.bytes_up + Flow.bytes_down).desc())
        .limit(10)
    )
    top_talkers = [{'ip': row[0], 'bytes': row[1]} for row in top_src_result.all()]
    
    # Top ports
    top_ports_result = await db.execute(
        select(Flow.dst_port, func.count(Flow.id).label('count'))
        .where(Flow.dataset_id == dataset_id)
        .group_by(Flow.dst_port)
        .order_by(func.count(Flow.id).desc())
        .limit(10)
    )
    top_ports = [{'port': row[0], 'count': row[1]} for row in top_ports_result.all()]
    
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


@router.delete("/{dataset_id}")
async def delete_dataset(dataset_id: str, db: AsyncSession = Depends(get_db)):
    """删除数据集"""
    result = await db.execute(
        select(Dataset).where(Dataset.id == dataset_id)
    )
    dataset = result.scalar_one_or_none()
    
    if not dataset:
        raise HTTPException(status_code=404, detail="Dataset not found")
    
    # 删除文件
    dataset_dir = settings.DATASETS_DIR / dataset_id
    if dataset_dir.exists():
        shutil.rmtree(dataset_dir)
    
    # 删除数据库记录（级联删除）
    await db.delete(dataset)
    await db.commit()
    
    return {"message": "Dataset deleted successfully"}
