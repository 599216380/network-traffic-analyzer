"""
检测规则配置API路由
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Dict, Any

from models import get_db
from models.database import DetectionRule as DetectionRuleModel
from models.schemas import DetectionRuleConfig, DetectionRuleResponse
from detection import create_default_engine

router = APIRouter(prefix="/rules", tags=["检测规则"])

# 全局检测引擎
detection_engine = create_default_engine()


@router.get("")
async def list_rules():
    """获取所有检测规则"""
    return {
        'rules': detection_engine.get_rules()
    }


@router.get("/{rule_id}")
async def get_rule(rule_id: str):
    """获取规则详情"""
    if rule_id not in detection_engine.rules:
        raise HTTPException(status_code=404, detail="规则不存在")
    
    rule = detection_engine.rules[rule_id]
    return {
        'rule_id': rule.rule_id,
        'name': rule.name,
        'alert_type': rule.alert_type.value,
        'severity': rule.severity.value,
        'enabled': rule.enabled,
        'config': rule.config
    }


@router.put("/{rule_id}/config")
async def update_rule_config(
    rule_id: str,
    config: DetectionRuleConfig
):
    """更新规则配置"""
    if rule_id not in detection_engine.rules:
        raise HTTPException(status_code=404, detail="规则不存在")
    
    rule = detection_engine.rules[rule_id]
    rule.enabled = config.enabled
    rule.severity = config.severity
    
    if config.config:
        rule.update_config(config.config)
    
    return {
        'message': '规则配置已更新',
        'rule_id': rule_id,
        'enabled': rule.enabled,
        'severity': rule.severity.value,
        'config': rule.config
    }


@router.post("/{rule_id}/enable")
async def enable_rule(rule_id: str):
    """启用规则"""
    if rule_id not in detection_engine.rules:
        raise HTTPException(status_code=404, detail="规则不存在")
    
    detection_engine.enable_rule(rule_id)
    
    return {'message': f'规则 {rule_id} 已启用'}


@router.post("/{rule_id}/disable")
async def disable_rule(rule_id: str):
    """禁用规则"""
    if rule_id not in detection_engine.rules:
        raise HTTPException(status_code=404, detail="规则不存在")
    
    detection_engine.disable_rule(rule_id)
    
    return {'message': f'规则 {rule_id} 已禁用'}


@router.get("/{rule_id}/thresholds")
async def get_rule_thresholds(rule_id: str):
    """获取规则阈值配置"""
    if rule_id not in detection_engine.rules:
        raise HTTPException(status_code=404, detail="规则不存在")
    
    rule = detection_engine.rules[rule_id]
    
    # 根据规则类型返回不同的阈值
    thresholds = {}
    
    if rule_id == 'port_scan_detector':
        thresholds = {
            'time_window': rule.get_config_value('time_window', 60),
            'min_ports': rule.get_config_value('min_ports', 10),
            'min_hosts': rule.get_config_value('min_hosts', 5)
        }
    elif rule_id == 'brute_force_detector':
        thresholds = {
            'time_window': rule.get_config_value('time_window', 300),
            'min_attempts': rule.get_config_value('min_attempts', 10),
            'target_ports': rule.get_config_value('target_ports', [22, 23, 3389])
        }
    elif rule_id == 'dns_tunnel_detector':
        thresholds = {
            'min_qname_length': rule.get_config_value('min_qname_length', 50),
            'min_entropy': rule.get_config_value('min_entropy', 3.5),
            'min_subdomain_levels': rule.get_config_value('min_subdomain_levels', 4),
            'nxdomain_ratio': rule.get_config_value('nxdomain_ratio', 0.3)
        }
    elif rule_id == 'c2_beacon_detector':
        thresholds = {
            'time_window': rule.get_config_value('time_window', 3600),
            'min_connections': rule.get_config_value('min_connections', 10),
            'variance_threshold': rule.get_config_value('variance_threshold', 0.15),
            'min_regularity_score': rule.get_config_value('min_regularity_score', 0.7)
        }
    
    return {
        'rule_id': rule_id,
        'thresholds': thresholds
    }


@router.put("/{rule_id}/thresholds")
async def update_rule_thresholds(
    rule_id: str,
    thresholds: Dict[str, Any]
):
    """更新规则阈值"""
    if rule_id not in detection_engine.rules:
        raise HTTPException(status_code=404, detail="规则不存在")
    
    detection_engine.update_rule_config(rule_id, thresholds)
    
    return {
        'message': '阈值已更新',
        'rule_id': rule_id,
        'thresholds': thresholds
    }
