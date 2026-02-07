"""
数据库模型定义
"""
from sqlalchemy import (
    Column, Integer, String, Float, DateTime, Text, Boolean,
    ForeignKey, Enum, JSON, Index, BigInteger
)
from sqlalchemy.orm import relationship, declarative_base
from sqlalchemy.sql import func
from datetime import datetime
import enum

Base = declarative_base()


class TaskStatus(str, enum.Enum):
    """任务状态"""
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


class AlertSeverity(str, enum.Enum):
    """告警严重程度"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(str, enum.Enum):
    """告警状态"""
    OPEN = "open"
    INVESTIGATING = "investigating"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class AlertType(str, enum.Enum):
    """告警类型"""
    PORT_SCAN = "port_scan"
    BRUTE_FORCE = "brute_force"
    DNS_TUNNEL = "dns_tunnel"
    C2_BEACON = "c2_beacon"
    SUSPICIOUS_DNS = "suspicious_dns"
    ANOMALY = "anomaly"


class Dataset(Base):
    """数据集（每次导入的pcap为一个数据集）"""
    __tablename__ = "datasets"
    
    id = Column(String(36), primary_key=True)  # UUID
    name = Column(String(255), nullable=False)
    filename = Column(String(255), nullable=False)
    filepath = Column(String(1024), nullable=False)
    file_size = Column(BigInteger, default=0)
    
    status = Column(Enum(TaskStatus), default=TaskStatus.PENDING)
    progress = Column(Float, default=0.0)  # 0-100
    error_message = Column(Text, nullable=True)
    
    # 统计信息
    total_packets = Column(Integer, default=0)
    total_bytes = Column(BigInteger, default=0)
    total_flows = Column(Integer, default=0)
    start_time = Column(DateTime, nullable=True)  # pcap中最早时间
    end_time = Column(DateTime, nullable=True)    # pcap中最晚时间
    
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # 关系
    flows = relationship("Flow", back_populates="dataset", cascade="all, delete-orphan")
    dns_events = relationship("DnsEvent", back_populates="dataset", cascade="all, delete-orphan")
    http_events = relationship("HttpEvent", back_populates="dataset", cascade="all, delete-orphan")
    tls_events = relationship("TlsEvent", back_populates="dataset", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="dataset", cascade="all, delete-orphan")


class Flow(Base):
    """网络流/会话"""
    __tablename__ = "flows"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    dataset_id = Column(String(36), ForeignKey("datasets.id"), nullable=False)
    
    # 五元组
    src_ip = Column(String(45), nullable=False)  # 支持IPv6
    dst_ip = Column(String(45), nullable=False)
    src_port = Column(Integer, nullable=False)
    dst_port = Column(Integer, nullable=False)
    protocol = Column(Integer, nullable=False)  # IP协议号: 6=TCP, 17=UDP, 1=ICMP
    
    # 时间
    ts_start = Column(DateTime, nullable=False)
    ts_end = Column(DateTime, nullable=False)
    duration = Column(Float, default=0.0)  # 秒
    
    # 双向统计
    packets_up = Column(Integer, default=0)    # 上行包数
    packets_down = Column(Integer, default=0)  # 下行包数
    bytes_up = Column(BigInteger, default=0)   # 上行字节
    bytes_down = Column(BigInteger, default=0) # 下行字节
    
    # TCP标志统计
    syn_count = Column(Integer, default=0)
    ack_count = Column(Integer, default=0)
    fin_count = Column(Integer, default=0)
    rst_count = Column(Integer, default=0)
    psh_count = Column(Integer, default=0)
    
    # 状态
    state = Column(String(32), default="unknown")  # established, failed, incomplete等
    
    # 应用层识别
    app_protocol = Column(String(32), nullable=True)  # HTTP, DNS, TLS等
    
    # 元数据
    first_packet_id = Column(Integer, nullable=True)  # 用于回溯
    last_packet_id = Column(Integer, nullable=True)
    
    created_at = Column(DateTime, default=func.now())
    
    # 关系
    dataset = relationship("Dataset", back_populates="flows")
    
    # 索引
    __table_args__ = (
        Index("idx_flow_dataset", "dataset_id"),
        Index("idx_flow_src_ip", "src_ip"),
        Index("idx_flow_dst_ip", "dst_ip"),
        Index("idx_flow_src_port", "src_port"),
        Index("idx_flow_dst_port", "dst_port"),
        Index("idx_flow_protocol", "protocol"),
        Index("idx_flow_ts_start", "ts_start"),
        Index("idx_flow_tuple", "src_ip", "dst_ip", "src_port", "dst_port", "protocol"),
    )


class DnsEvent(Base):
    """DNS查询事件"""
    __tablename__ = "dns_events"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    dataset_id = Column(String(36), ForeignKey("datasets.id"), nullable=False)
    flow_id = Column(Integer, ForeignKey("flows.id"), nullable=True)
    
    timestamp = Column(DateTime, nullable=False)
    src_ip = Column(String(45), nullable=False)
    dst_ip = Column(String(45), nullable=False)
    
    # DNS字段
    transaction_id = Column(Integer, nullable=True)
    query_name = Column(String(512), nullable=False)  # 查询域名
    query_type = Column(String(16), nullable=True)    # A, AAAA, MX, TXT等
    query_class = Column(String(8), default="IN")
    
    # 响应
    is_response = Column(Boolean, default=False)
    response_code = Column(String(16), nullable=True)  # NOERROR, NXDOMAIN等
    answers = Column(JSON, nullable=True)  # 响应记录列表
    ttl = Column(Integer, nullable=True)
    
    # 分析特征
    qname_length = Column(Integer, default=0)
    subdomain_count = Column(Integer, default=0)  # 子域层级数
    entropy = Column(Float, nullable=True)  # 域名熵值
    
    packet_id = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=func.now())
    
    # 关系
    dataset = relationship("Dataset", back_populates="dns_events")
    
    __table_args__ = (
        Index("idx_dns_dataset", "dataset_id"),
        Index("idx_dns_query_name", "query_name"),
        Index("idx_dns_src_ip", "src_ip"),
        Index("idx_dns_timestamp", "timestamp"),
        Index("idx_dns_response_code", "response_code"),
    )


class HttpEvent(Base):
    """HTTP请求事件"""
    __tablename__ = "http_events"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    dataset_id = Column(String(36), ForeignKey("datasets.id"), nullable=False)
    flow_id = Column(Integer, ForeignKey("flows.id"), nullable=True)
    
    timestamp = Column(DateTime, nullable=False)
    src_ip = Column(String(45), nullable=False)
    dst_ip = Column(String(45), nullable=False)
    src_port = Column(Integer, nullable=False)
    dst_port = Column(Integer, nullable=False)
    
    # 请求
    method = Column(String(16), nullable=True)  # GET, POST等
    host = Column(String(512), nullable=True)
    uri = Column(String(2048), nullable=True)
    user_agent = Column(String(1024), nullable=True)
    referer = Column(String(2048), nullable=True)
    content_type = Column(String(256), nullable=True)
    content_length = Column(Integer, nullable=True)
    
    # 响应
    status_code = Column(Integer, nullable=True)
    response_content_type = Column(String(256), nullable=True)
    response_content_length = Column(Integer, nullable=True)
    
    # 其他
    cookies = Column(Text, nullable=True)
    headers = Column(JSON, nullable=True)
    
    packet_id = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=func.now())
    
    # 关系
    dataset = relationship("Dataset", back_populates="http_events")
    
    __table_args__ = (
        Index("idx_http_dataset", "dataset_id"),
        Index("idx_http_host", "host"),
        Index("idx_http_src_ip", "src_ip"),
        Index("idx_http_status_code", "status_code"),
        Index("idx_http_timestamp", "timestamp"),
    )


class TlsEvent(Base):
    """TLS/SSL事件"""
    __tablename__ = "tls_events"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    dataset_id = Column(String(36), ForeignKey("datasets.id"), nullable=False)
    flow_id = Column(Integer, ForeignKey("flows.id"), nullable=True)
    
    timestamp = Column(DateTime, nullable=False)
    src_ip = Column(String(45), nullable=False)
    dst_ip = Column(String(45), nullable=False)
    src_port = Column(Integer, nullable=False)
    dst_port = Column(Integer, nullable=False)
    
    # TLS字段
    sni = Column(String(512), nullable=True)  # Server Name Indication
    ja3_hash = Column(String(64), nullable=True)  # JA3指纹
    ja3s_hash = Column(String(64), nullable=True)  # JA3S指纹
    
    tls_version = Column(String(16), nullable=True)
    cipher_suites = Column(JSON, nullable=True)
    extensions = Column(JSON, nullable=True)
    
    # 证书信息（简化）
    cert_subject = Column(String(512), nullable=True)
    cert_issuer = Column(String(512), nullable=True)
    cert_serial = Column(String(128), nullable=True)
    cert_not_before = Column(DateTime, nullable=True)
    cert_not_after = Column(DateTime, nullable=True)
    
    packet_id = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=func.now())
    
    # 关系
    dataset = relationship("Dataset", back_populates="tls_events")
    
    __table_args__ = (
        Index("idx_tls_dataset", "dataset_id"),
        Index("idx_tls_sni", "sni"),
        Index("idx_tls_ja3", "ja3_hash"),
        Index("idx_tls_timestamp", "timestamp"),
    )


class Alert(Base):
    """安全告警"""
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    dataset_id = Column(String(36), ForeignKey("datasets.id"), nullable=False)
    
    # 告警基本信息
    alert_type = Column(Enum(AlertType), nullable=False)
    severity = Column(Enum(AlertSeverity), default=AlertSeverity.MEDIUM)
    status = Column(Enum(AlertStatus), default=AlertStatus.OPEN)
    
    title = Column(String(512), nullable=False)
    description = Column(Text, nullable=True)
    
    # 时间范围
    ts_start = Column(DateTime, nullable=False)
    ts_end = Column(DateTime, nullable=False)
    
    # 涉及的主体
    src_ip = Column(String(45), nullable=True)
    dst_ip = Column(String(45), nullable=True)
    src_ips = Column(JSON, nullable=True)  # 多个源IP
    dst_ips = Column(JSON, nullable=True)  # 多个目的IP
    dst_ports = Column(JSON, nullable=True)  # 涉及端口
    
    # 检测指标
    score = Column(Float, default=0.0)  # 置信度评分 0-100
    indicators = Column(JSON, nullable=True)  # 具体指标值
    
    # 证据
    evidence = Column(JSON, nullable=True)  # 证据详情
    related_flow_ids = Column(JSON, nullable=True)  # 关联的flow ID列表
    related_dns_ids = Column(JSON, nullable=True)  # 关联的DNS事件ID
    related_http_ids = Column(JSON, nullable=True)  # 关联的HTTP事件ID
    sample_packets = Column(JSON, nullable=True)  # 样本包摘要
    
    # 规则信息
    rule_id = Column(String(64), nullable=True)
    rule_name = Column(String(256), nullable=True)
    
    # 处置
    tags = Column(JSON, nullable=True)
    notes = Column(Text, nullable=True)
    handled_by = Column(String(128), nullable=True)
    handled_at = Column(DateTime, nullable=True)
    
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # 关系
    dataset = relationship("Dataset", back_populates="alerts")
    
    __table_args__ = (
        Index("idx_alert_dataset", "dataset_id"),
        Index("idx_alert_type", "alert_type"),
        Index("idx_alert_severity", "severity"),
        Index("idx_alert_status", "status"),
        Index("idx_alert_src_ip", "src_ip"),
        Index("idx_alert_created", "created_at"),
    )


class DetectionRule(Base):
    """检测规则配置"""
    __tablename__ = "detection_rules"
    
    id = Column(String(64), primary_key=True)
    name = Column(String(256), nullable=False)
    description = Column(Text, nullable=True)
    
    rule_type = Column(Enum(AlertType), nullable=False)
    enabled = Column(Boolean, default=True)
    severity = Column(Enum(AlertSeverity), default=AlertSeverity.MEDIUM)
    
    # 配置参数（JSON格式）
    config = Column(JSON, nullable=True)
    
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
