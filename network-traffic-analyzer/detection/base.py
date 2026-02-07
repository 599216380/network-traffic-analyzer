"""
检测规则基类
"""
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum

from models.database import AlertType, AlertSeverity


@dataclass
class DetectionResult:
    """检测结果"""
    rule_id: str
    rule_name: str
    alert_type: AlertType
    severity: AlertSeverity
    
    title: str
    description: str
    
    ts_start: datetime
    ts_end: datetime
    
    # 涉及的主体
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_ips: List[str] = field(default_factory=list)
    dst_ips: List[str] = field(default_factory=list)
    dst_ports: List[int] = field(default_factory=list)
    
    # 评分与指标
    score: float = 0.0
    indicators: Dict[str, Any] = field(default_factory=dict)
    
    # 证据
    evidence: Dict[str, Any] = field(default_factory=dict)
    related_flow_ids: List[int] = field(default_factory=list)
    related_dns_ids: List[int] = field(default_factory=list)
    related_http_ids: List[int] = field(default_factory=list)


class DetectionRule(ABC):
    """检测规则基类"""
    
    def __init__(self, rule_id: str, name: str, alert_type: AlertType, 
                 severity: AlertSeverity = AlertSeverity.MEDIUM,
                 enabled: bool = True, config: Dict[str, Any] = None,
                 description: str = ""):
        self.rule_id = rule_id
        self.name = name
        self.description = description
        self.alert_type = alert_type
        self.severity = severity
        self.enabled = enabled
        self.config = config or {}
    
    @abstractmethod
    def detect(self, flows: List[Any], dns_events: List[Any] = None,
               http_events: List[Any] = None) -> List[DetectionResult]:
        """
        执行检测
        
        Args:
            flows: 流记录列表
            dns_events: DNS事件列表
            http_events: HTTP事件列表
        
        Returns:
            检测结果列表
        """
        pass
    
    def get_config_value(self, key: str, default: Any = None) -> Any:
        """获取配置值"""
        return self.config.get(key, default)
    
    def update_config(self, config: Dict[str, Any]) -> None:
        """更新配置"""
        self.config.update(config)


class DetectionEngine:
    """检测引擎 - 管理和执行所有检测规则"""
    
    def __init__(self):
        self.rules: Dict[str, DetectionRule] = {}
    
    def register_rule(self, rule: DetectionRule) -> None:
        """注册检测规则"""
        self.rules[rule.rule_id] = rule
    
    def unregister_rule(self, rule_id: str) -> None:
        """注销检测规则"""
        if rule_id in self.rules:
            del self.rules[rule_id]
    
    def enable_rule(self, rule_id: str) -> None:
        """启用规则"""
        if rule_id in self.rules:
            self.rules[rule_id].enabled = True
    
    def disable_rule(self, rule_id: str) -> None:
        """禁用规则"""
        if rule_id in self.rules:
            self.rules[rule_id].enabled = False
    
    def update_rule_config(self, rule_id: str, config: Dict[str, Any]) -> None:
        """更新规则配置"""
        if rule_id in self.rules:
            self.rules[rule_id].update_config(config)
    
    def run_all(self, flows: List[Any], dns_events: List[Any] = None,
                http_events: List[Any] = None) -> List[DetectionResult]:
        """
        运行所有启用的检测规则
        
        Returns:
            所有检测结果
        """
        results = []
        
        for rule in self.rules.values():
            if rule.enabled:
                try:
                    rule_results = rule.detect(flows, dns_events, http_events)
                    results.extend(rule_results)
                except Exception as e:
                    print(f"规则 {rule.rule_id} 执行失败: {e}")
        
        return results
    
    def run_rule(self, rule_id: str, flows: List[Any], 
                 dns_events: List[Any] = None,
                 http_events: List[Any] = None) -> List[DetectionResult]:
        """运行指定规则"""
        if rule_id not in self.rules:
            return []
        
        rule = self.rules[rule_id]
        if not rule.enabled:
            return []
        
        return rule.detect(flows, dns_events, http_events)
    
    def get_rules(self) -> List[Dict[str, Any]]:
        """获取所有规则信息"""
        return [
            {
                'rule_id': rule.rule_id,
                'name': rule.name,
                'alert_type': rule.alert_type.value,
                'severity': rule.severity.value,
                'enabled': rule.enabled,
                'config': rule.config
            }
            for rule in self.rules.values()
        ]
