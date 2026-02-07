"""
检测模块初始化
"""
from .base import DetectionRule, DetectionResult, DetectionEngine
from .port_scan import PortScanDetector
from .brute_force import BruteForceDetector
from .dns_tunnel import DnsTunnelDetector
from .c2_beacon import C2BeaconDetector


def create_default_engine() -> DetectionEngine:
    """创建带有默认规则的检测引擎"""
    engine = DetectionEngine()
    
    # 注册所有检测规则
    engine.register_rule(PortScanDetector())
    engine.register_rule(BruteForceDetector())
    engine.register_rule(DnsTunnelDetector())
    engine.register_rule(C2BeaconDetector())
    
    return engine


__all__ = [
    "DetectionRule", "DetectionResult", "DetectionEngine",
    "PortScanDetector", "BruteForceDetector", "DnsTunnelDetector", "C2BeaconDetector",
    "create_default_engine"
]
