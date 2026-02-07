"""
检测规则管理API
"""
from typing import Optional, Dict, Any

from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from models import DetectionRuleConfig, DetectionRuleResponse, get_db
from detection import create_default_engine

router = APIRouter(prefix="/rules", tags=["detection-rules"])

# 全局检测引擎实例
detection_engine = create_default_engine()


@router.get("")
async def list_rules():
    """获取所有检测规则"""
    return detection_engine.get_rules()


class CreateRuleRequest(BaseModel):
    rule_id: str
    name: str
    description: Optional[str] = None
    alert_type: str = "anomaly"
    severity: str = "medium"
    enabled: bool = True
    config: Optional[Dict[str, Any]] = None


@router.post("")
async def create_rule(request: CreateRuleRequest):
    """创建新的检测规则"""
    from detection.base import DetectionRule, DetectionResult
    from models.database import AlertSeverity, AlertType
    
    # 检查规则ID是否已存在
    if request.rule_id in detection_engine.rules:
        raise HTTPException(status_code=400, detail="Rule ID already exists")
    
    # 创建自定义规则类
    class CustomRule(DetectionRule):
        def __init__(self):
            super().__init__(
                rule_id=request.rule_id,
                name=request.name,
                alert_type=AlertType(request.alert_type),
                severity=AlertSeverity(request.severity),
                enabled=request.enabled,
                description=request.description or ""
            )
            if request.config:
                self.config = request.config
        
        def detect(self, flows, dns_events=None, http_events=None):
            # 自定义规则暂不执行实际检测
            return []
    
    # 注册规则到检测引擎
    custom_rule = CustomRule()
    detection_engine.register_rule(custom_rule)
    
    return {
        "message": "Rule created successfully",
        "rule": {
            "rule_id": request.rule_id,
            "name": request.name,
            "description": request.description,
            "alert_type": request.alert_type,
            "severity": request.severity,
            "enabled": request.enabled
        }
    }


@router.get("/{rule_id}")
async def get_rule(rule_id: str):
    """获取单个规则详情"""
    rules = detection_engine.get_rules()
    
    for rule in rules:
        if rule['rule_id'] == rule_id:
            return rule
    
    raise HTTPException(status_code=404, detail="Rule not found")


@router.patch("/{rule_id}")
async def update_rule(rule_id: str, config: DetectionRuleConfig):
    """更新规则配置"""
    if rule_id not in detection_engine.rules:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    rule = detection_engine.rules[rule_id]
    
    rule.enabled = config.enabled
    rule.severity = config.severity
    
    if config.config:
        rule.update_config(config.config)
    
    return {
        "message": "Rule updated successfully",
        "rule": {
            "rule_id": rule.rule_id,
            "name": rule.name,
            "enabled": rule.enabled,
            "severity": rule.severity.value,
            "config": rule.config
        }
    }


@router.post("/{rule_id}/enable")
async def enable_rule(rule_id: str):
    """启用规则"""
    if rule_id not in detection_engine.rules:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    detection_engine.enable_rule(rule_id)
    
    return {"message": f"Rule {rule_id} enabled"}


@router.post("/{rule_id}/disable")
async def disable_rule(rule_id: str):
    """禁用规则"""
    if rule_id not in detection_engine.rules:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    detection_engine.disable_rule(rule_id)
    
    return {"message": f"Rule {rule_id} disabled"}
