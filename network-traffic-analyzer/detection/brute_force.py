"""
暴力破解检测规则

检测逻辑：
1. 对SSH/RDP/Telnet等认证端口的高频连接
2. 短时间内大量短连接（尝试-失败-重试模式）
3. HTTP 401/403响应码的高频出现
"""
from typing import List, Dict, Any, Set
from datetime import datetime, timedelta
from collections import defaultdict

from detection.base import DetectionRule, DetectionResult
from models.database import AlertType, AlertSeverity
from config.settings import get_settings

settings = get_settings()


class BruteForceDetector(DetectionRule):
    """暴力破解检测器"""
    
    # 目标认证端口
    AUTH_PORTS = {
        22: 'SSH',
        23: 'Telnet',
        21: 'FTP',
        25: 'SMTP',
        110: 'POP3',
        143: 'IMAP',
        3389: 'RDP',
        5900: 'VNC',
        1433: 'MSSQL',
        3306: 'MySQL',
        5432: 'PostgreSQL',
        6379: 'Redis',
        27017: 'MongoDB',
        8080: 'HTTP',
        80: 'HTTP',
        443: 'HTTPS'
    }
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(
            rule_id="brute_force_detector",
            name="暴力破解检测",
            alert_type=AlertType.BRUTE_FORCE,
            severity=AlertSeverity.HIGH,
            config=config or {}
        )
        
        # 配置
        self.time_window = self.get_config_value('time_window', settings.BRUTEFORCE_TIME_WINDOW)
        self.min_attempts = self.get_config_value('min_attempts', settings.BRUTEFORCE_MIN_ATTEMPTS)
        self.target_ports = self.get_config_value('target_ports', settings.BRUTEFORCE_PORTS)
    
    def detect(self, flows: List[Any], dns_events: List[Any] = None,
               http_events: List[Any] = None) -> List[DetectionResult]:
        """执行暴力破解检测"""
        results = []
        
        # 网络层检测：针对认证端口的高频短连接
        network_results = self._detect_network_bruteforce(flows)
        results.extend(network_results)
        
        # HTTP层检测：401/403响应码
        if http_events:
            http_results = self._detect_http_bruteforce(http_events, flows)
            results.extend(http_results)
        
        return results
    
    def _detect_network_bruteforce(self, flows: List[Any]) -> List[DetectionResult]:
        """基于网络层的暴力破解检测"""
        results = []
        
        # 筛选目标端口的TCP流
        target_flows = [
            f for f in flows 
            if f.protocol == 6 and f.dst_port in self.target_ports
        ]
        
        if not target_flows:
            return results
        
        # 按(源IP, 目标IP, 目标端口)分组
        groups = defaultdict(list)
        for flow in target_flows:
            key = (flow.src_ip, flow.dst_ip, flow.dst_port)
            groups[key].append(flow)
        
        for (src_ip, dst_ip, dst_port), flow_group in groups.items():
            result = self._analyze_bruteforce_pattern(src_ip, dst_ip, dst_port, flow_group)
            if result:
                results.append(result)
        
        return results
    
    def _analyze_bruteforce_pattern(self, src_ip: str, dst_ip: str, dst_port: int,
                                   flows: List[Any]) -> DetectionResult:
        """分析暴力破解模式"""
        if len(flows) < self.min_attempts:
            return None
        
        # 按时间排序
        sorted_flows = sorted(flows, key=lambda f: f.ts_start)
        
        # 计算时间范围
        ts_start = sorted_flows[0].ts_start
        ts_end = sorted_flows[-1].ts_end
        duration = (ts_end - ts_start).total_seconds()
        
        # 检查是否在时间窗口内
        if duration > self.time_window:
            # 使用滑动窗口找到最密集的区间
            window_counts = self._sliding_window_count(sorted_flows)
            if max(window_counts.values()) < self.min_attempts:
                return None
        
        total_attempts = len(flows)
        
        # 分析连接特征
        short_connections = 0  # 短连接数
        failed_connections = 0  # 失败连接数
        total_bytes = 0
        flow_ids = []
        
        for flow in flows:
            flow_ids.append(flow.id if hasattr(flow, 'id') else None)
            total_bytes += flow.bytes_up + flow.bytes_down
            
            # 短连接：持续时间短且数据量小
            if flow.duration < 5 and flow.bytes_up + flow.bytes_down < 1000:
                short_connections += 1
            
            # 失败连接
            if flow.state in ('reset', 'syn_only', 'incomplete'):
                failed_connections += 1
        
        short_ratio = short_connections / total_attempts
        failure_rate = failed_connections / total_attempts
        avg_bytes = total_bytes / total_attempts
        attempts_per_minute = total_attempts / (duration / 60) if duration > 0 else total_attempts
        
        # 暴力破解特征：高频、短连接、高失败率
        is_bruteforce = (
            total_attempts >= self.min_attempts and
            (short_ratio > 0.5 or failure_rate > 0.3 or attempts_per_minute > 10)
        )
        
        if not is_bruteforce:
            return None
        
        # 计算评分
        score = min(100, 
            (total_attempts / self.min_attempts) * 20 +
            short_ratio * 30 +
            failure_rate * 30 +
            min(attempts_per_minute / 20, 1) * 20
        )
        
        # 严重程度
        if score >= 80 or total_attempts >= 100:
            severity = AlertSeverity.CRITICAL
        elif score >= 60 or total_attempts >= 50:
            severity = AlertSeverity.HIGH
        else:
            severity = AlertSeverity.MEDIUM
        
        service_name = self.AUTH_PORTS.get(dst_port, 'Unknown')
        
        return DetectionResult(
            rule_id=self.rule_id,
            rule_name=self.name,
            alert_type=self.alert_type,
            severity=severity,
            title=f"疑似暴力破解: {src_ip} → {dst_ip}:{dst_port} ({service_name})",
            description=f"源IP {src_ip} 在 {duration:.1f}秒 内对 {dst_ip}:{dst_port} ({service_name}) "
                       f"发起 {total_attempts} 次连接尝试，短连接比例 {short_ratio*100:.1f}%，"
                       f"失败率 {failure_rate*100:.1f}%",
            ts_start=ts_start,
            ts_end=ts_end,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_ports=[dst_port],
            score=score,
            indicators={
                'total_attempts': total_attempts,
                'duration_seconds': duration,
                'attempts_per_minute': round(attempts_per_minute, 2),
                'short_connection_ratio': round(short_ratio, 3),
                'failure_rate': round(failure_rate, 3),
                'avg_bytes_per_connection': round(avg_bytes, 2),
                'target_service': service_name
            },
            evidence={
                'time_range': f"{ts_start} - {ts_end}",
                'connection_states': self._get_state_distribution(flows)
            },
            related_flow_ids=[fid for fid in flow_ids if fid is not None]
        )
    
    def _sliding_window_count(self, sorted_flows: List[Any]) -> Dict[datetime, int]:
        """滑动窗口计数"""
        window_seconds = self.time_window
        counts = defaultdict(int)
        
        for flow in sorted_flows:
            window_key = flow.ts_start.replace(second=0, microsecond=0)
            counts[window_key] += 1
        
        return counts
    
    def _get_state_distribution(self, flows: List[Any]) -> Dict[str, int]:
        """获取连接状态分布"""
        states = defaultdict(int)
        for flow in flows:
            states[flow.state] += 1
        return dict(states)
    
    def _detect_http_bruteforce(self, http_events: List[Any], 
                                flows: List[Any]) -> List[DetectionResult]:
        """基于HTTP层的暴力破解检测（401/403）"""
        results = []
        
        # 筛选认证失败响应
        auth_failures = [
            e for e in http_events 
            if hasattr(e, 'status_code') and e.status_code in (401, 403)
        ]
        
        if len(auth_failures) < self.min_attempts:
            return results
        
        # 按(源IP, 目标主机)分组
        groups = defaultdict(list)
        for event in auth_failures:
            host = event.host if hasattr(event, 'host') else event.dst_ip
            key = (event.src_ip, host)
            groups[key].append(event)
        
        for (src_ip, host), events in groups.items():
            if len(events) < self.min_attempts:
                continue
            
            # 分析
            sorted_events = sorted(events, key=lambda e: e.timestamp)
            ts_start = sorted_events[0].timestamp
            ts_end = sorted_events[-1].timestamp
            duration = (ts_end - ts_start).total_seconds()
            
            if duration > self.time_window:
                continue
            
            total_failures = len(events)
            
            # 统计URI
            uri_counts = defaultdict(int)
            for e in events:
                uri = e.uri if hasattr(e, 'uri') else '/'
                uri_counts[uri] += 1
            
            # 评分
            score = min(100, (total_failures / self.min_attempts) * 50 + 50)
            
            severity = AlertSeverity.HIGH if score >= 70 else AlertSeverity.MEDIUM
            
            result = DetectionResult(
                rule_id=self.rule_id + "_http",
                rule_name=self.name + "(HTTP认证)",
                alert_type=self.alert_type,
                severity=severity,
                title=f"疑似HTTP暴力破解: {src_ip} → {host}",
                description=f"源IP {src_ip} 在 {duration:.1f}秒 内对 {host} "
                           f"产生 {total_failures} 次认证失败 (401/403)",
                ts_start=ts_start,
                ts_end=ts_end,
                src_ip=src_ip,
                dst_ip=host,
                score=score,
                indicators={
                    'total_auth_failures': total_failures,
                    'duration_seconds': duration,
                    'target_uris': dict(uri_counts)
                },
                evidence={
                    'sample_uris': list(uri_counts.keys())[:10],
                    'status_codes': [401, 403]
                },
                related_http_ids=[e.id if hasattr(e, 'id') else None for e in events]
            )
            results.append(result)
        
        return results
