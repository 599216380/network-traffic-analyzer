"""
DNS隧道检测规则

检测逻辑：
1. 域名长度异常（> 50字符）
2. 子域层级过深（> 4级）
3. 域名字符熵值高（> 3.5，表示随机性高）
4. NXDOMAIN比例高
5. TXT查询比例高
6. 单一域名的查询频率异常
"""
from typing import List, Dict, Any, Set, Tuple
from datetime import datetime, timedelta
from collections import defaultdict
import math

from detection.base import DetectionRule, DetectionResult
from models.database import AlertType, AlertSeverity
from config.settings import get_settings
from parsers.pcap_parser import calculate_entropy

settings = get_settings()


class DnsTunnelDetector(DetectionRule):
    """DNS隧道检测器"""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(
            rule_id="dns_tunnel_detector",
            name="DNS隧道检测",
            alert_type=AlertType.DNS_TUNNEL,
            severity=AlertSeverity.HIGH,
            config=config or {}
        )
        
        # 配置阈值
        self.min_qname_length = self.get_config_value('min_qname_length', 
                                                       settings.DNS_TUNNEL_MIN_QNAME_LENGTH)
        self.min_entropy = self.get_config_value('min_entropy',
                                                  settings.DNS_TUNNEL_MIN_ENTROPY)
        self.min_subdomain_levels = self.get_config_value('min_subdomain_levels',
                                                           settings.DNS_TUNNEL_MIN_SUBDOMAIN_LEVELS)
        self.nxdomain_ratio = self.get_config_value('nxdomain_ratio',
                                                     settings.DNS_TUNNEL_NXDOMAIN_RATIO)
    
    def detect(self, flows: List[Any], dns_events: List[Any] = None,
               http_events: List[Any] = None) -> List[DetectionResult]:
        """执行DNS隧道检测"""
        results = []
        
        if not dns_events:
            return results
        
        # 1. 检测单个异常DNS查询
        anomaly_results = self._detect_anomalous_queries(dns_events)
        results.extend(anomaly_results)
        
        # 2. 检测按域名聚合的异常模式
        domain_results = self._detect_domain_patterns(dns_events)
        results.extend(domain_results)
        
        # 3. 检测高频DNS查询（潜在数据外泄）
        frequency_results = self._detect_high_frequency(dns_events)
        results.extend(frequency_results)
        
        return results
    
    def _detect_anomalous_queries(self, dns_events: List[Any]) -> List[DetectionResult]:
        """检测单个异常DNS查询"""
        results = []
        
        # 按源IP聚合异常查询
        suspicious_queries: Dict[str, List] = defaultdict(list)
        
        for event in dns_events:
            # 跳过响应
            if hasattr(event, 'is_response') and event.is_response:
                continue
            
            qname = event.query_name if hasattr(event, 'query_name') else ''
            if not qname:
                continue
            
            # 计算特征
            qname_length = len(qname)
            subdomain_count = qname.count('.') + 1 if qname else 0
            
            # 计算熵（只对第一个子域）
            parts = qname.split('.')
            first_subdomain = parts[0] if parts else ''
            entropy = calculate_entropy(first_subdomain)
            
            # 判断是否异常
            is_suspicious = (
                qname_length >= self.min_qname_length or
                subdomain_count >= self.min_subdomain_levels or
                entropy >= self.min_entropy
            )
            
            if is_suspicious:
                src_ip = event.src_ip if hasattr(event, 'src_ip') else 'unknown'
                suspicious_queries[src_ip].append({
                    'event': event,
                    'qname': qname,
                    'qname_length': qname_length,
                    'subdomain_count': subdomain_count,
                    'entropy': entropy,
                    'query_type': event.query_type if hasattr(event, 'query_type') else 'A'
                })
        
        # 生成告警
        for src_ip, queries in suspicious_queries.items():
            if len(queries) >= 3:  # 至少3个异常查询才告警
                result = self._create_anomaly_alert(src_ip, queries)
                if result:
                    results.append(result)
        
        return results
    
    def _create_anomaly_alert(self, src_ip: str, queries: List[Dict]) -> DetectionResult:
        """创建异常DNS告警"""
        # 计算聚合指标
        avg_length = sum(q['qname_length'] for q in queries) / len(queries)
        avg_entropy = sum(q['entropy'] for q in queries) / len(queries)
        max_subdomain = max(q['subdomain_count'] for q in queries)
        
        # 获取时间范围
        timestamps = [q['event'].timestamp for q in queries if hasattr(q['event'], 'timestamp')]
        ts_start = min(timestamps) if timestamps else datetime.now()
        ts_end = max(timestamps) if timestamps else datetime.now()
        
        # 提取根域名
        root_domains = self._extract_root_domains([q['qname'] for q in queries])
        
        # 评分
        score = min(100,
            (avg_length / self.min_qname_length) * 25 +
            (avg_entropy / self.min_entropy) * 35 +
            (max_subdomain / self.min_subdomain_levels) * 20 +
            min(len(queries) / 10, 1) * 20
        )
        
        # 严重程度
        if score >= 80 or len(queries) >= 20:
            severity = AlertSeverity.HIGH
        elif score >= 50:
            severity = AlertSeverity.MEDIUM
        else:
            severity = AlertSeverity.LOW
        
        # TXT查询比例
        txt_count = sum(1 for q in queries if q['query_type'] == 'TXT')
        txt_ratio = txt_count / len(queries) if queries else 0
        
        return DetectionResult(
            rule_id=self.rule_id,
            rule_name=self.name,
            alert_type=self.alert_type,
            severity=severity,
            title=f"疑似DNS隧道: {src_ip} 发起异常DNS查询",
            description=f"源IP {src_ip} 发起 {len(queries)} 个异常DNS查询，"
                       f"平均域名长度 {avg_length:.1f}，平均熵值 {avg_entropy:.2f}，"
                       f"涉及根域名: {', '.join(list(root_domains)[:5])}",
            ts_start=ts_start,
            ts_end=ts_end,
            src_ip=src_ip,
            score=score,
            indicators={
                'total_anomalous_queries': len(queries),
                'avg_qname_length': round(avg_length, 2),
                'avg_entropy': round(avg_entropy, 3),
                'max_subdomain_levels': max_subdomain,
                'txt_query_ratio': round(txt_ratio, 3),
                'unique_root_domains': len(root_domains)
            },
            evidence={
                'sample_queries': [q['qname'] for q in queries[:10]],
                'root_domains': list(root_domains)[:10],
                'query_type_distribution': self._get_query_type_distribution(queries)
            },
            related_dns_ids=[q['event'].id if hasattr(q['event'], 'id') else None for q in queries]
        )
    
    def _detect_domain_patterns(self, dns_events: List[Any]) -> List[DetectionResult]:
        """检测按域名聚合的异常模式"""
        results = []
        
        # 按根域名聚合
        domain_queries: Dict[str, List] = defaultdict(list)
        
        for event in dns_events:
            qname = event.query_name if hasattr(event, 'query_name') else ''
            if not qname:
                continue
            
            root_domain = self._get_root_domain(qname)
            domain_queries[root_domain].append(event)
        
        # 分析每个根域名
        for root_domain, events in domain_queries.items():
            if len(events) < 5:  # 至少5个查询
                continue
            
            # 统计NXDOMAIN
            nxdomain_count = sum(
                1 for e in events 
                if hasattr(e, 'response_code') and e.response_code == 'NXDOMAIN'
            )
            response_count = sum(
                1 for e in events 
                if hasattr(e, 'is_response') and e.is_response
            )
            
            if response_count == 0:
                continue
            
            nxdomain_ratio = nxdomain_count / response_count
            
            # 高NXDOMAIN比例可能表示域名生成算法（DGA）
            if nxdomain_ratio >= self.nxdomain_ratio:
                result = self._create_nxdomain_alert(root_domain, events, nxdomain_ratio)
                results.append(result)
        
        return results
    
    def _create_nxdomain_alert(self, root_domain: str, events: List[Any],
                               nxdomain_ratio: float) -> DetectionResult:
        """创建NXDOMAIN高比例告警"""
        # 获取源IP
        src_ips = set(e.src_ip for e in events if hasattr(e, 'src_ip'))
        
        # 时间范围
        timestamps = [e.timestamp for e in events if hasattr(e, 'timestamp')]
        ts_start = min(timestamps) if timestamps else datetime.now()
        ts_end = max(timestamps) if timestamps else datetime.now()
        
        # 唯一子域名
        unique_subdomains = set(
            e.query_name for e in events if hasattr(e, 'query_name')
        )
        
        score = min(100, nxdomain_ratio * 100 + len(unique_subdomains) / 10)
        
        return DetectionResult(
            rule_id=self.rule_id + "_nxdomain",
            rule_name=self.name + "(高NXDOMAIN)",
            alert_type=AlertType.SUSPICIOUS_DNS,
            severity=AlertSeverity.MEDIUM,
            title=f"异常DNS模式: {root_domain} NXDOMAIN比例 {nxdomain_ratio*100:.1f}%",
            description=f"域名 {root_domain} 的DNS查询NXDOMAIN比例达到 {nxdomain_ratio*100:.1f}%，"
                       f"共 {len(unique_subdomains)} 个唯一子域名，可能为DGA域名",
            ts_start=ts_start,
            ts_end=ts_end,
            src_ips=list(src_ips),
            score=score,
            indicators={
                'root_domain': root_domain,
                'total_queries': len(events),
                'nxdomain_ratio': round(nxdomain_ratio, 3),
                'unique_subdomains': len(unique_subdomains),
                'unique_sources': len(src_ips)
            },
            evidence={
                'sample_nxdomains': [
                    e.query_name for e in events 
                    if hasattr(e, 'response_code') and e.response_code == 'NXDOMAIN'
                ][:10]
            },
            related_dns_ids=[e.id if hasattr(e, 'id') else None for e in events]
        )
    
    def _detect_high_frequency(self, dns_events: List[Any]) -> List[DetectionResult]:
        """检测高频DNS查询"""
        results = []
        
        # 按(源IP, 根域名, 分钟)聚合
        frequency: Dict[Tuple, List] = defaultdict(list)
        
        for event in dns_events:
            if hasattr(event, 'is_response') and event.is_response:
                continue
            
            qname = event.query_name if hasattr(event, 'query_name') else ''
            src_ip = event.src_ip if hasattr(event, 'src_ip') else ''
            timestamp = event.timestamp if hasattr(event, 'timestamp') else datetime.now()
            
            root_domain = self._get_root_domain(qname)
            minute_key = timestamp.replace(second=0, microsecond=0)
            
            key = (src_ip, root_domain, minute_key)
            frequency[key].append(event)
        
        # 检测异常高频
        for (src_ip, root_domain, minute), events in frequency.items():
            if len(events) >= 30:  # 每分钟30+查询
                # 检查是否都是唯一子域名（表示数据编码）
                unique_names = set(e.query_name for e in events if hasattr(e, 'query_name'))
                
                if len(unique_names) >= len(events) * 0.8:  # 80%以上唯一
                    result = DetectionResult(
                        rule_id=self.rule_id + "_highfreq",
                        rule_name=self.name + "(高频)",
                        alert_type=self.alert_type,
                        severity=AlertSeverity.HIGH,
                        title=f"高频DNS外泄: {src_ip} → {root_domain}",
                        description=f"源IP {src_ip} 在1分钟内对 {root_domain} 发起 {len(events)} 次DNS查询，"
                                   f"其中 {len(unique_names)} 个唯一子域名，疑似DNS隧道数据外泄",
                        ts_start=minute,
                        ts_end=minute + timedelta(minutes=1),
                        src_ip=src_ip,
                        score=min(100, len(events) / 30 * 100),
                        indicators={
                            'queries_per_minute': len(events),
                            'unique_subdomains': len(unique_names),
                            'root_domain': root_domain
                        },
                        evidence={
                            'sample_queries': list(unique_names)[:20]
                        },
                        related_dns_ids=[e.id if hasattr(e, 'id') else None for e in events]
                    )
                    results.append(result)
        
        return results
    
    def _get_root_domain(self, qname: str) -> str:
        """提取根域名（后两级）"""
        if not qname:
            return ''
        
        parts = qname.rstrip('.').split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return qname
    
    def _extract_root_domains(self, qnames: List[str]) -> Set[str]:
        """提取所有根域名"""
        return set(self._get_root_domain(q) for q in qnames if q)
    
    def _get_query_type_distribution(self, queries: List[Dict]) -> Dict[str, int]:
        """获取查询类型分布"""
        distribution = defaultdict(int)
        for q in queries:
            qtype = q.get('query_type', 'A')
            distribution[qtype] += 1
        return dict(distribution)
