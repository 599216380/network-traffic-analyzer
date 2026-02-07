"""
Pydantic Schemas for API request/response
"""
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


# ============ Enums ============
class TaskStatusEnum(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


class AlertSeverityEnum(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatusEnum(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class AlertTypeEnum(str, Enum):
    PORT_SCAN = "port_scan"
    BRUTE_FORCE = "brute_force"
    DNS_TUNNEL = "dns_tunnel"
    C2_BEACON = "c2_beacon"
    SUSPICIOUS_DNS = "suspicious_dns"
    ANOMALY = "anomaly"


# ============ Dataset Schemas ============
class DatasetBase(BaseModel):
    name: str


class DatasetCreate(DatasetBase):
    pass


class DatasetResponse(DatasetBase):
    id: str
    filename: str
    file_size: int
    status: TaskStatusEnum
    progress: float
    error_message: Optional[str] = None
    total_packets: int = 0
    total_bytes: int = 0
    total_flows: int = 0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class DatasetListResponse(BaseModel):
    total: int
    items: List[DatasetResponse]


class DatasetStats(BaseModel):
    total_packets: int
    total_bytes: int
    total_flows: int
    unique_src_ips: int
    unique_dst_ips: int
    protocol_distribution: Dict[str, int]
    top_talkers: List[Dict[str, Any]]
    top_ports: List[Dict[str, Any]]
    time_range: Dict[str, Optional[datetime]]


# ============ Flow Schemas ============
class FlowBase(BaseModel):
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int


class FlowResponse(FlowBase):
    id: int
    dataset_id: str
    ts_start: datetime
    ts_end: datetime
    duration: float
    packets_up: int
    packets_down: int
    bytes_up: int
    bytes_down: int
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    state: str
    app_protocol: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class FlowListResponse(BaseModel):
    total: int
    items: List[FlowResponse]


class FlowQuery(BaseModel):
    dataset_id: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[int] = None
    time_from: Optional[datetime] = None
    time_to: Optional[datetime] = None
    app_protocol: Optional[str] = None
    min_bytes: Optional[int] = None
    max_bytes: Optional[int] = None
    limit: int = Field(default=100, le=1000)
    offset: int = Field(default=0, ge=0)
    order_by: str = Field(default="ts_start")
    order_desc: bool = True


# ============ DNS Event Schemas ============
class DnsEventResponse(BaseModel):
    id: int
    dataset_id: str
    flow_id: Optional[int] = None
    timestamp: datetime
    src_ip: str
    dst_ip: str
    transaction_id: Optional[int] = None
    query_name: str
    query_type: Optional[str] = None
    is_response: bool
    response_code: Optional[str] = None
    answers: Optional[List[Dict[str, Any]]] = None
    ttl: Optional[int] = None
    qname_length: int
    subdomain_count: int
    entropy: Optional[float] = None

    class Config:
        from_attributes = True


class DnsEventListResponse(BaseModel):
    total: int
    items: List[DnsEventResponse]


class DnsQuery(BaseModel):
    dataset_id: Optional[str] = None
    src_ip: Optional[str] = None
    query_name: Optional[str] = None
    query_type: Optional[str] = None
    response_code: Optional[str] = None
    time_from: Optional[datetime] = None
    time_to: Optional[datetime] = None
    min_entropy: Optional[float] = None
    limit: int = Field(default=100, le=1000)
    offset: int = Field(default=0, ge=0)


# ============ HTTP Event Schemas ============
class HttpEventResponse(BaseModel):
    id: int
    dataset_id: str
    flow_id: Optional[int] = None
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    method: Optional[str] = None
    host: Optional[str] = None
    uri: Optional[str] = None
    user_agent: Optional[str] = None
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    content_length: Optional[int] = None

    class Config:
        from_attributes = True


class HttpEventListResponse(BaseModel):
    total: int
    items: List[HttpEventResponse]


# ============ TLS Event Schemas ============
class TlsEventResponse(BaseModel):
    id: int
    dataset_id: str
    flow_id: Optional[int] = None
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    sni: Optional[str] = None
    ja3_hash: Optional[str] = None
    tls_version: Optional[str] = None
    cert_subject: Optional[str] = None
    cert_issuer: Optional[str] = None

    class Config:
        from_attributes = True


class TlsEventListResponse(BaseModel):
    total: int
    items: List[TlsEventResponse]


# ============ Alert Schemas ============
class AlertBase(BaseModel):
    alert_type: AlertTypeEnum
    severity: AlertSeverityEnum
    title: str
    description: Optional[str] = None


class AlertResponse(AlertBase):
    id: int
    dataset_id: str
    status: AlertStatusEnum
    ts_start: datetime
    ts_end: datetime
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_ips: Optional[List[str]] = None
    dst_ips: Optional[List[str]] = None
    dst_ports: Optional[List[int]] = None
    score: float
    indicators: Optional[Dict[str, Any]] = None
    evidence: Optional[Dict[str, Any]] = None
    related_flow_ids: Optional[List[int]] = None
    related_dns_ids: Optional[List[int]] = None
    related_http_ids: Optional[List[int]] = None
    rule_id: Optional[str] = None
    rule_name: Optional[str] = None
    tags: Optional[List[str]] = None
    notes: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class AlertListResponse(BaseModel):
    total: int
    items: List[AlertResponse]


class AlertQuery(BaseModel):
    dataset_id: Optional[str] = None
    alert_type: Optional[AlertTypeEnum] = None
    severity: Optional[AlertSeverityEnum] = None
    status: Optional[AlertStatusEnum] = None
    src_ip: Optional[str] = None
    time_from: Optional[datetime] = None
    time_to: Optional[datetime] = None
    limit: int = Field(default=100, le=1000)
    offset: int = Field(default=0, ge=0)


class AlertUpdate(BaseModel):
    status: Optional[AlertStatusEnum] = None
    severity: Optional[AlertSeverityEnum] = None
    tags: Optional[List[str]] = None
    notes: Optional[str] = None


# ============ Detection Rule Schemas ============
class DetectionRuleConfig(BaseModel):
    enabled: bool = True
    severity: AlertSeverityEnum = AlertSeverityEnum.MEDIUM
    config: Optional[Dict[str, Any]] = None


class DetectionRuleResponse(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    rule_type: AlertTypeEnum
    enabled: bool
    severity: AlertSeverityEnum
    config: Optional[Dict[str, Any]] = None

    class Config:
        from_attributes = True


# ============ Dashboard/Stats Schemas ============
class TimeSeriesPoint(BaseModel):
    timestamp: datetime
    value: float


class DashboardStats(BaseModel):
    total_datasets: int
    total_flows: int
    total_bytes: int
    total_alerts: int
    alerts_by_severity: Dict[str, int]
    alerts_by_type: Dict[str, int]
    top_src_ips: List[Dict[str, Any]]
    top_dst_ips: List[Dict[str, Any]]
    top_domains: List[Dict[str, Any]]
    protocol_distribution: Dict[str, int]
    traffic_timeline: List[TimeSeriesPoint]


# ============ Export Schemas ============
class ExportRequest(BaseModel):
    dataset_id: str
    export_type: str = Field(default="flows", pattern="^(flows|dns|http|alerts)$")
    format: str = Field(default="csv", pattern="^(csv|json|html)$")
    filters: Optional[Dict[str, Any]] = None


class ExportResponse(BaseModel):
    task_id: str
    status: str
    download_url: Optional[str] = None
