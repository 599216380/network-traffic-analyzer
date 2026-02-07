"""
项目配置管理
"""
from pydantic_settings import BaseSettings
from pathlib import Path
from typing import Optional
import os


class Settings(BaseSettings):
    """应用配置"""
    
    # 基础配置
    APP_NAME: str = "Network Traffic Analyzer"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True
    
    # 路径配置
    BASE_DIR: Path = Path(__file__).resolve().parent.parent
    DATA_DIR: Path = BASE_DIR / "data"
    DATASETS_DIR: Path = DATA_DIR / "datasets"
    UPLOADS_DIR: Path = DATA_DIR / "uploads"
    EXPORTS_DIR: Path = DATA_DIR / "exports"
    
    # 数据库配置
    DATABASE_URL: str = f"sqlite+aiosqlite:///{BASE_DIR}/data/traffic_analyzer.db"
    
    # 上传配置
    MAX_UPLOAD_SIZE: int = 500 * 1024 * 1024  # 500MB
    ALLOWED_EXTENSIONS: list = [".pcap", ".pcapng", ".cap"]
    
    # 解析配置
    FLOW_IDLE_TIMEOUT: int = 60  # 流空闲超时（秒）
    FLOW_ACTIVE_TIMEOUT: int = 3600  # 流活跃超时（秒）
    
    # 检测配置
    DETECTION_ENABLED: bool = True
    
    # 端口扫描检测阈值
    PORTSCAN_TIME_WINDOW: int = 60  # 秒
    PORTSCAN_MIN_PORTS: int = 10  # 最少目标端口数
    PORTSCAN_MIN_HOSTS: int = 5   # 最少目标主机数
    
    # 暴力破解检测阈值
    BRUTEFORCE_TIME_WINDOW: int = 300  # 秒
    BRUTEFORCE_MIN_ATTEMPTS: int = 10  # 最少尝试次数
    BRUTEFORCE_PORTS: list = [22, 23, 3389, 5900, 21, 25, 110, 143]  # 目标端口
    
    # DNS隧道检测阈值
    DNS_TUNNEL_MIN_QNAME_LENGTH: int = 50  # 域名长度阈值
    DNS_TUNNEL_MIN_ENTROPY: float = 3.5  # 熵值阈值
    DNS_TUNNEL_MIN_SUBDOMAIN_LEVELS: int = 4  # 子域层级阈值
    DNS_TUNNEL_NXDOMAIN_RATIO: float = 0.3  # NXDOMAIN比例阈值
    
    # C2 Beacon检测阈值
    BEACON_TIME_WINDOW: int = 3600  # 秒
    BEACON_MIN_CONNECTIONS: int = 10  # 最少连接数
    BEACON_INTERVAL_VARIANCE_THRESHOLD: float = 0.15  # 间隔方差阈值（相对值）
    BEACON_MIN_REGULARITY_SCORE: float = 0.7  # 最低规律性评分
    
    # API配置
    API_PREFIX: str = "/api/v1"
    CORS_ORIGINS: list = ["*"]
    
    class Config:
        env_file = ".env"
        case_sensitive = True


def get_settings() -> Settings:
    """获取配置单例"""
    return Settings()


# 创建必要目录
settings = get_settings()
for dir_path in [settings.DATA_DIR, settings.DATASETS_DIR, settings.UPLOADS_DIR, settings.EXPORTS_DIR]:
    dir_path.mkdir(parents=True, exist_ok=True)
