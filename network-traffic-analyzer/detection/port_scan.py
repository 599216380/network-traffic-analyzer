"""
端口扫描检测规则

检测逻辑：
1. 同一源IP在短时间内连接多个目的端口 → 水平扫描
2. 同一源IP在短时间内连接多个目的IP的同一端口 → 垂直扫描
3. 高SYN比例、高失败率（RST/无ACK）增加置信度
"""
from typing import List, Dict, Any, Set
from datetime import datetime, timedelta
from collections import defaultdict

from detection.base import DetectionRule, DetectionResult
from models.database import AlertType, AlertSeverity
from config.settings import get_settings

settings = get_settings()


class PortScanDetector(DetectionRule):
    """端口扫描检测器"""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(
            rule_id="port_scan_detector",
            name="端口扫描检测",
            alert_type=AlertType.PORT_SCAN,
            severity=AlertSeverity.MEDIUM,
            config=config or {}
        )
        
        # 默认阈值
        self.time_window = self.get_config_value('time_window', settings.PORTSCAN_TIME_WINDOW)
        self.min_ports = self.get_config_value('min_ports', settings.PORTSCAN_MIN_PORTS)
        self.min_hosts = self.get_config_value('min_hosts', settings.PORTSCAN_MIN_HOSTS)
    
    def detect(self, flows: List[Any], dns_events: List[Any] = None,
               http_events: List[Any] = None) -> List[DetectionResult]:
        """执行端口扫描检测"""
        results = []
        
        # 只分析TCP流
        tcp_flows = [f for f in flows if f.protocol == 6]
        
        if not tcp_flows:
            return results
        
        # 按时间窗口分组
        window_data = self._group_by_time_window(tcp_flows)
        
        for (src_ip, window_start), flow_group in window_data.items():
            # 水平扫描检测：同一源扫描多个端口
            horizontal_result = self._detect_horizontal_scan(src_ip, window_start, flow_group)
            if horizontal_result:
                results.append(horizontal_result)
            
            # 垂直扫描检测：同一源扫描多个主机的同一端口
            vertical_result = self._detect_vertical_scan(src_ip, window_start, flow_group)
            if vertical_result:
                results.append(vertical_result)
        
        return results
    
    def _group_by_time_window(self, flows: List[Any]) -> Dict:
        """按源IP和时间窗口分组"""
        window_seconds = self.time_window
        groups = defaultdict(list)
        
        for flow in flows:
            # 计算时间窗口
            window_start = flow.ts_start.replace(
                second=(flow.ts_start.second // window_seconds) * window_seconds,
                microsecond=0
            )
            key = (flow.src_ip, window_start)
            groups[key].append(flow)
        
        return groups
    
    def _detect_horizontal_scan(self, src_ip: str, window_start: datetime,
                                flows: List[Any]) -> DetectionResult:
        """检测水平扫描（扫描多个端口）"""
        # 统计目标端口
        dst_ports: Set[int] = set()
        dst_ips: Set[str] = set()
        failed_count = 0
        syn_only_count = 0
        total_count = len(flows)
        flow_ids = []
        
        for flow in flows:
            dst_ports.add(flow.dst_port)
            dst_ips.add(flow.dst_ip)
            flow_ids.append(flow.id if hasattr(flow, 'id') else None)
            
            # 检查失败状态
            if flow.state in ('syn_only', 'reset', 'incomplete'):
                failed_count += 1
            if flow.state == 'syn_only':
                syn_only_count += 1
        
        unique_ports = len(dst_ports)
        
        # 判断是否为扫描
        if unique_ports < self.min_ports:
            return None
        
        # 计算评分
        failure_rate = failed_count / total_count if total_count > 0 else 0
        syn_ratio = syn_only_count / total_count if total_count > 0 else 0
        
        # 评分公式：端口数量 + 失败率 + SYN比例
        score = min(100, (unique_ports / self.min_ports) * 30 + failure_rate * 40 + syn_ratio * 30)
        
        # 确定严重程度
        if score >= 80 or unique_ports >= 100:
            severity = AlertSeverity.HIGH
        elif score >= 50 or unique_ports >= 50:
            severity = AlertSeverity.MEDIUM
        else:
            severity = AlertSeverity.LOW
        
        window_end = window_start + timedelta(seconds=self.time_window)
        
        return DetectionResult(
            rule_id=self.rule_id,
            rule_name=self.name,
            alert_type=self.alert_type,
            severity=severity,
            title=f"检测到端口扫描: {src_ip} 扫描 {unique_ports} 个端口",
            description=f"源IP {src_ip} 在 {self.time_window}秒 内尝试连接 {unique_ports} 个不同端口，"
                       f"涉及 {len(dst_ips)} 个目标主机，失败率 {failure_rate*100:.1f}%",
            ts_start=window_start,
            ts_end=window_end,
            src_ip=src_ip,
            dst_ips=list(dst_ips),
            dst_ports=sorted(list(dst_ports)),
            score=score,
            indicators={
                'unique_ports': unique_ports,
                'unique_hosts': len(dst_ips),
                'total_connections': total_count,
                'failed_connections': failed_count,
                'failure_rate': failure_rate,
                'syn_only_ratio': syn_ratio,
                'scan_type': 'horizontal'
            },
            evidence={
                'time_window': self.time_window,
                'sample_ports': sorted(list(dst_ports))[:20],
                'sample_hosts': list(dst_ips)[:10]
            },
            related_flow_ids=[fid for fid in flow_ids if fid is not None]
        )
    
    def _detect_vertical_scan(self, src_ip: str, window_start: datetime,
                              flows: List[Any]) -> DetectionResult:
        """检测垂直扫描（扫描多个主机的同一端口）"""
        # 按目标端口分组统计目标IP
        port_to_hosts: Dict[int, Set[str]] = defaultdict(set)
        port_to_flows: Dict[int, List] = defaultdict(list)
        
        for flow in flows:
            port_to_hosts[flow.dst_port].add(flow.dst_ip)
            port_to_flows[flow.dst_port].append(flow)
        
        # 找出扫描最多主机的端口
        max_hosts = 0
        target_port = 0
        
        for port, hosts in port_to_hosts.items():
            if len(hosts) > max_hosts:
                max_hosts = len(hosts)
                target_port = port
        
        if max_hosts < self.min_hosts:
            return None
        
        target_flows = port_to_flows[target_port]
        dst_ips = list(port_to_hosts[target_port])
        
        # 统计失败
        failed_count = sum(1 for f in target_flows if f.state in ('syn_only', 'reset', 'incomplete'))
        total_count = len(target_flows)
        failure_rate = failed_count / total_count if total_count > 0 else 0
        
        # 评分
        score = min(100, (max_hosts / self.min_hosts) * 40 + failure_rate * 40 + 20)
        
        # 严重程度
        if score >= 80 or max_hosts >= 50:
            severity = AlertSeverity.HIGH
        elif score >= 50 or max_hosts >= 20:
            severity = AlertSeverity.MEDIUM
        else:
            severity = AlertSeverity.LOW
        
        window_end = window_start + timedelta(seconds=self.time_window)
        
        # 识别常见端口
        port_service = self._get_port_service(target_port)
        
        return DetectionResult(
            rule_id=self.rule_id + "_vertical",
            rule_name=self.name + "(垂直扫描)",
            alert_type=self.alert_type,
            severity=severity,
            title=f"检测到端口扫描: {src_ip} 扫描 {max_hosts} 台主机的端口 {target_port}",
            description=f"源IP {src_ip} 在 {self.time_window}秒 内对 {max_hosts} 台主机的端口 "
                       f"{target_port} ({port_service}) 发起连接，失败率 {failure_rate*100:.1f}%",
            ts_start=window_start,
            ts_end=window_end,
            src_ip=src_ip,
            dst_ips=dst_ips,
            dst_ports=[target_port],
            score=score,
            indicators={
                'target_port': target_port,
                'target_service': port_service,
                'unique_hosts': max_hosts,
                'total_connections': total_count,
                'failed_connections': failed_count,
                'failure_rate': failure_rate,
                'scan_type': 'vertical'
            },
            evidence={
                'time_window': self.time_window,
                'sample_hosts': dst_ips[:20]
            },
            related_flow_ids=[f.id if hasattr(f, 'id') else None for f in target_flows]
        )
    
    def _get_port_service(self, port: int) -> str:
        """获取端口对应的服务名"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
            993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 1521: 'Oracle',
            3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
            6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 27017: 'MongoDB'
        }
        return services.get(port, 'Unknown')
