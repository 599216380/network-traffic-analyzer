"""
C2 Beacon检测规则

检测逻辑：
1. 周期性连接（固定间隔，低方差）
2. 小包高频（数据量小但连接次数多）
3. 心跳模式（规律性时间间隔）
4. 可疑目的地（非常见端口、稀有ASN等）
"""
from typing import List, Dict, Any, Tuple
from datetime import datetime, timedelta
from collections import defaultdict
import statistics
import math

from detection.base import DetectionRule, DetectionResult
from models.database import AlertType, AlertSeverity
from config.settings import get_settings

settings = get_settings()


class C2BeaconDetector(DetectionRule):
    """C2 Beacon检测器"""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(
            rule_id="c2_beacon_detector",
            name="C2 Beacon检测",
            alert_type=AlertType.C2_BEACON,
            severity=AlertSeverity.CRITICAL,
            config=config or {}
        )
        
        # 配置
        self.time_window = self.get_config_value('time_window', settings.BEACON_TIME_WINDOW)
        self.min_connections = self.get_config_value('min_connections', settings.BEACON_MIN_CONNECTIONS)
        self.variance_threshold = self.get_config_value('variance_threshold', 
                                                        settings.BEACON_INTERVAL_VARIANCE_THRESHOLD)
        self.min_regularity_score = self.get_config_value('min_regularity_score',
                                                          settings.BEACON_MIN_REGULARITY_SCORE)
    
    def detect(self, flows: List[Any], dns_events: List[Any] = None,
               http_events: List[Any] = None) -> List[DetectionResult]:
        """执行C2 Beacon检测"""
        results = []
        
        if not flows:
            return results
        
        # 按(源IP, 目的IP, 目的端口)分组
        connection_groups = self._group_connections(flows)
        
        for key, flow_group in connection_groups.items():
            if len(flow_group) < self.min_connections:
                continue
            
            src_ip, dst_ip, dst_port = key
            
            # 分析周期性
            result = self._analyze_periodicity(src_ip, dst_ip, dst_port, flow_group)
            if result:
                results.append(result)
        
        return results
    
    def _group_connections(self, flows: List[Any]) -> Dict[Tuple, List]:
        """按连接三元组分组"""
        groups = defaultdict(list)
        
        for flow in flows:
            # 只分析TCP/UDP
            if flow.protocol not in (6, 17):
                continue
            
            key = (flow.src_ip, flow.dst_ip, flow.dst_port)
            groups[key].append(flow)
        
        return groups
    
    def _analyze_periodicity(self, src_ip: str, dst_ip: str, dst_port: int,
                            flows: List[Any]) -> DetectionResult:
        """分析连接的周期性"""
        # 按时间排序
        sorted_flows = sorted(flows, key=lambda f: f.ts_start)
        
        # 计算时间间隔
        intervals = []
        for i in range(1, len(sorted_flows)):
            interval = (sorted_flows[i].ts_start - sorted_flows[i-1].ts_start).total_seconds()
            if interval > 0:  # 排除同时间的连接
                intervals.append(interval)
        
        if len(intervals) < self.min_connections - 1:
            return None
        
        # 计算统计特征
        mean_interval = statistics.mean(intervals)
        
        if mean_interval <= 0:
            return None
        
        # 计算标准差和变异系数
        if len(intervals) >= 2:
            std_interval = statistics.stdev(intervals)
            cv = std_interval / mean_interval  # 变异系数
        else:
            std_interval = 0
            cv = 0
        
        # 计算规律性评分
        regularity_score = self._calculate_regularity_score(intervals, mean_interval)
        
        # 判断是否为beacon
        is_beacon = (
            cv <= self.variance_threshold or
            regularity_score >= self.min_regularity_score
        )
        
        if not is_beacon:
            return None
        
        # 计算数据特征
        total_bytes_up = sum(f.bytes_up for f in sorted_flows)
        total_bytes_down = sum(f.bytes_down for f in sorted_flows)
        avg_bytes = (total_bytes_up + total_bytes_down) / len(sorted_flows)
        
        # 小包高频特征
        small_packet_ratio = sum(1 for f in sorted_flows if f.bytes_up + f.bytes_down < 1000) / len(sorted_flows)
        
        # 时间范围
        ts_start = sorted_flows[0].ts_start
        ts_end = sorted_flows[-1].ts_end
        duration = (ts_end - ts_start).total_seconds()
        
        # 综合评分
        score = self._calculate_beacon_score(
            cv, regularity_score, small_packet_ratio, 
            len(sorted_flows), mean_interval
        )
        
        if score < 50:
            return None
        
        # 严重程度
        if score >= 85:
            severity = AlertSeverity.CRITICAL
        elif score >= 70:
            severity = AlertSeverity.HIGH
        else:
            severity = AlertSeverity.MEDIUM
        
        # 识别常见beacon间隔
        beacon_pattern = self._identify_beacon_pattern(mean_interval)
        
        return DetectionResult(
            rule_id=self.rule_id,
            rule_name=self.name,
            alert_type=self.alert_type,
            severity=severity,
            title=f"疑似C2 Beacon: {src_ip} → {dst_ip}:{dst_port}",
            description=f"源IP {src_ip} 与 {dst_ip}:{dst_port} 之间检测到周期性通信，"
                       f"平均间隔 {mean_interval:.1f}秒，变异系数 {cv:.3f}，"
                       f"规律性评分 {regularity_score:.2f}，{beacon_pattern}",
            ts_start=ts_start,
            ts_end=ts_end,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_ports=[dst_port],
            score=score,
            indicators={
                'total_connections': len(sorted_flows),
                'duration_seconds': round(duration, 2),
                'mean_interval': round(mean_interval, 2),
                'std_interval': round(std_interval, 2),
                'coefficient_of_variation': round(cv, 4),
                'regularity_score': round(regularity_score, 3),
                'small_packet_ratio': round(small_packet_ratio, 3),
                'avg_bytes_per_connection': round(avg_bytes, 2),
                'total_bytes_up': total_bytes_up,
                'total_bytes_down': total_bytes_down,
                'beacon_pattern': beacon_pattern
            },
            evidence={
                'interval_distribution': self._get_interval_distribution(intervals),
                'connection_timeline': self._get_connection_timeline(sorted_flows[:20]),
                'sample_intervals': intervals[:20]
            },
            related_flow_ids=[f.id if hasattr(f, 'id') else None for f in sorted_flows]
        )
    
    def _calculate_regularity_score(self, intervals: List[float], mean_interval: float) -> float:
        """
        计算规律性评分
        
        基于以下特征：
        1. 间隔接近平均值的比例
        2. 间隔分布的集中程度
        """
        if not intervals or mean_interval <= 0:
            return 0.0
        
        # 计算偏差在10%以内的间隔比例
        tolerance = mean_interval * 0.1
        close_to_mean = sum(1 for i in intervals if abs(i - mean_interval) <= tolerance)
        close_ratio = close_to_mean / len(intervals)
        
        # 计算偏差在20%以内的比例
        tolerance_20 = mean_interval * 0.2
        within_20 = sum(1 for i in intervals if abs(i - mean_interval) <= tolerance_20)
        within_20_ratio = within_20 / len(intervals)
        
        # 综合评分
        score = (close_ratio * 0.6 + within_20_ratio * 0.4)
        
        return score
    
    def _calculate_beacon_score(self, cv: float, regularity: float, 
                               small_packet_ratio: float, connection_count: int,
                               mean_interval: float) -> float:
        """计算beacon综合评分"""
        score = 0.0
        
        # 变异系数评分（越低越可疑）
        if cv <= 0.05:
            score += 40
        elif cv <= 0.1:
            score += 30
        elif cv <= 0.15:
            score += 20
        elif cv <= 0.2:
            score += 10
        
        # 规律性评分
        score += regularity * 30
        
        # 小包比例评分
        score += small_packet_ratio * 15
        
        # 连接数量评分
        if connection_count >= 50:
            score += 10
        elif connection_count >= 20:
            score += 5
        
        # 典型beacon间隔加分
        typical_intervals = [1, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600]
        for ti in typical_intervals:
            if abs(mean_interval - ti) / ti < 0.1:  # 10%容差
                score += 5
                break
        
        return min(100, score)
    
    def _identify_beacon_pattern(self, mean_interval: float) -> str:
        """识别beacon模式"""
        patterns = [
            (1, "1秒心跳"),
            (5, "5秒心跳"),
            (10, "10秒心跳"),
            (15, "15秒心跳"),
            (30, "30秒心跳"),
            (60, "1分钟心跳"),
            (120, "2分钟心跳"),
            (300, "5分钟心跳"),
            (600, "10分钟心跳"),
            (900, "15分钟心跳"),
            (1800, "30分钟心跳"),
            (3600, "1小时心跳")
        ]
        
        for interval, name in patterns:
            if abs(mean_interval - interval) / interval < 0.1:
                return f"疑似{name}模式"
        
        if mean_interval < 10:
            return "高频短间隔通信"
        elif mean_interval < 60:
            return "分钟级周期通信"
        elif mean_interval < 3600:
            return "小时内周期通信"
        else:
            return "长周期通信"
    
    def _get_interval_distribution(self, intervals: List[float]) -> Dict[str, int]:
        """获取间隔分布"""
        buckets = {
            '<1s': 0, '1-5s': 0, '5-30s': 0, '30s-1m': 0,
            '1-5m': 0, '5-30m': 0, '30m-1h': 0, '>1h': 0
        }
        
        for interval in intervals:
            if interval < 1:
                buckets['<1s'] += 1
            elif interval < 5:
                buckets['1-5s'] += 1
            elif interval < 30:
                buckets['5-30s'] += 1
            elif interval < 60:
                buckets['30s-1m'] += 1
            elif interval < 300:
                buckets['1-5m'] += 1
            elif interval < 1800:
                buckets['5-30m'] += 1
            elif interval < 3600:
                buckets['30m-1h'] += 1
            else:
                buckets['>1h'] += 1
        
        return {k: v for k, v in buckets.items() if v > 0}
    
    def _get_connection_timeline(self, flows: List[Any]) -> List[Dict]:
        """获取连接时间线"""
        timeline = []
        for flow in flows:
            timeline.append({
                'timestamp': flow.ts_start.isoformat() if hasattr(flow.ts_start, 'isoformat') else str(flow.ts_start),
                'bytes_up': flow.bytes_up,
                'bytes_down': flow.bytes_down,
                'duration': flow.duration
            })
        return timeline
