"""
Flow聚合器 - 将数据包聚合为会话流
"""
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from collections import defaultdict
import dpkt

from parsers.pcap_parser import PacketInfo, get_normalized_five_tuple


@dataclass
class FlowRecord:
    """流记录"""
    # 五元组
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    
    # 时间
    ts_start: datetime = None
    ts_end: datetime = None
    
    # 双向统计
    packets_up: int = 0
    packets_down: int = 0
    bytes_up: int = 0
    bytes_down: int = 0
    
    # TCP标志统计
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    
    # 状态
    state: str = "unknown"
    
    # 应用层
    app_protocol: Optional[str] = None
    
    # 包ID范围
    first_packet_id: Optional[int] = None
    last_packet_id: Optional[int] = None
    
    # 关联的事件
    dns_events: List[Dict] = field(default_factory=list)
    http_events: List[Dict] = field(default_factory=list)
    tls_events: List[Dict] = field(default_factory=list)
    
    @property
    def duration(self) -> float:
        """流持续时间（秒）"""
        if self.ts_start and self.ts_end:
            return (self.ts_end - self.ts_start).total_seconds()
        return 0.0
    
    @property
    def total_packets(self) -> int:
        return self.packets_up + self.packets_down
    
    @property
    def total_bytes(self) -> int:
        return self.bytes_up + self.bytes_down
    
    def to_dict(self) -> Dict:
        """转换为字典"""
        return {
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'ts_start': self.ts_start,
            'ts_end': self.ts_end,
            'duration': self.duration,
            'packets_up': self.packets_up,
            'packets_down': self.packets_down,
            'bytes_up': self.bytes_up,
            'bytes_down': self.bytes_down,
            'syn_count': self.syn_count,
            'ack_count': self.ack_count,
            'fin_count': self.fin_count,
            'rst_count': self.rst_count,
            'psh_count': self.psh_count,
            'state': self.state,
            'app_protocol': self.app_protocol,
            'first_packet_id': self.first_packet_id,
            'last_packet_id': self.last_packet_id,
        }


class FlowAggregator:
    """流聚合器"""
    
    def __init__(self, idle_timeout: int = 60, active_timeout: int = 3600):
        """
        初始化聚合器
        
        Args:
            idle_timeout: 空闲超时时间（秒），超过此时间无新包则结束流
            active_timeout: 活跃超时时间（秒），流最大持续时间
        """
        self.idle_timeout = timedelta(seconds=idle_timeout)
        self.active_timeout = timedelta(seconds=active_timeout)
        
        # 活跃流表: key = normalized_five_tuple, value = FlowRecord
        self.active_flows: Dict[Tuple, FlowRecord] = {}
        
        # 已完成的流
        self.completed_flows: List[FlowRecord] = []
        
        # DNS事件缓存（用于关联）
        self.dns_events: List[Dict] = []
        
        # HTTP事件缓存
        self.http_events: List[Dict] = []
        
        # TLS事件缓存
        self.tls_events: List[Dict] = []
        
        # 统计
        self.total_packets = 0
        self.total_bytes = 0
    
    def process_packet(self, packet: PacketInfo) -> Optional[FlowRecord]:
        """
        处理单个数据包
        
        Returns:
            如果流完成，返回FlowRecord；否则返回None
        """
        self.total_packets += 1
        self.total_bytes += packet.ip_len
        
        # 提取应用层事件
        if packet.dns_data:
            self._add_dns_event(packet)
        if packet.http_data:
            self._add_http_event(packet)
        if packet.tls_data:
            self._add_tls_event(packet)
        
        # 获取归一化五元组
        norm_tuple = get_normalized_five_tuple(packet)
        key = norm_tuple[:5]  # (ip1, ip2, port1, port2, proto)
        is_original_direction = norm_tuple[5]
        
        # 查找或创建流
        if key in self.active_flows:
            flow = self.active_flows[key]
            completed = self._update_flow(flow, packet, is_original_direction)
            
            if completed:
                del self.active_flows[key]
                self._finalize_flow(flow)
                self.completed_flows.append(flow)
                return flow
        else:
            # 创建新流
            if is_original_direction:
                flow = FlowRecord(
                    src_ip=packet.src_ip,
                    dst_ip=packet.dst_ip,
                    src_port=packet.src_port,
                    dst_port=packet.dst_port,
                    protocol=packet.ip_proto
                )
            else:
                flow = FlowRecord(
                    src_ip=packet.dst_ip,
                    dst_ip=packet.src_ip,
                    src_port=packet.dst_port,
                    dst_port=packet.src_port,
                    protocol=packet.ip_proto
                )
            
            flow.ts_start = packet.timestamp
            flow.ts_end = packet.timestamp
            flow.first_packet_id = packet.packet_id
            flow.last_packet_id = packet.packet_id
            
            self._update_flow_stats(flow, packet, is_original_direction)
            self.active_flows[key] = flow
        
        return None
    
    def _update_flow(self, flow: FlowRecord, packet: PacketInfo, is_original: bool) -> bool:
        """
        更新流统计
        
        Returns:
            True if flow should be completed
        """
        # 检查是否超时
        time_since_last = packet.timestamp - flow.ts_end
        duration = packet.timestamp - flow.ts_start
        
        if time_since_last > self.idle_timeout or duration > self.active_timeout:
            return True
        
        # 更新时间
        flow.ts_end = packet.timestamp
        flow.last_packet_id = packet.packet_id
        
        # 更新统计
        self._update_flow_stats(flow, packet, is_original)
        
        # 检查TCP结束标志
        if packet.ip_proto == 6:  # TCP
            if packet.tcp_flags & dpkt.tcp.TH_RST:
                flow.state = "reset"
                return True
            if flow.fin_count >= 2:  # 双向FIN
                flow.state = "closed"
                return True
        
        return False
    
    def _update_flow_stats(self, flow: FlowRecord, packet: PacketInfo, is_original: bool) -> None:
        """更新流的统计信息"""
        # 方向性统计
        if is_original:
            flow.packets_up += 1
            flow.bytes_up += packet.ip_len
        else:
            flow.packets_down += 1
            flow.bytes_down += packet.ip_len
        
        # TCP标志统计
        if packet.ip_proto == 6:  # TCP
            if packet.tcp_flags & dpkt.tcp.TH_SYN:
                flow.syn_count += 1
            if packet.tcp_flags & dpkt.tcp.TH_ACK:
                flow.ack_count += 1
            if packet.tcp_flags & dpkt.tcp.TH_FIN:
                flow.fin_count += 1
            if packet.tcp_flags & dpkt.tcp.TH_RST:
                flow.rst_count += 1
            if packet.tcp_flags & dpkt.tcp.TH_PUSH:
                flow.psh_count += 1
        
        # 应用层协议
        if packet.app_protocol and not flow.app_protocol:
            flow.app_protocol = packet.app_protocol
    
    def _finalize_flow(self, flow: FlowRecord) -> None:
        """完成流的最终处理"""
        # 确定TCP状态
        if flow.protocol == 6:  # TCP
            if flow.syn_count >= 2 and flow.ack_count >= 1:
                if flow.fin_count >= 2:
                    flow.state = "closed"
                elif flow.rst_count > 0:
                    flow.state = "reset"
                else:
                    flow.state = "established"
            elif flow.syn_count == 1 and flow.ack_count == 0:
                flow.state = "syn_only"  # 可能是扫描
            else:
                flow.state = "incomplete"
        elif flow.protocol == 17:  # UDP
            flow.state = "udp"
        else:
            flow.state = "other"
    
    def _add_dns_event(self, packet: PacketInfo) -> None:
        """添加DNS事件"""
        if packet.dns_data:
            event = {
                'timestamp': packet.timestamp,
                'src_ip': packet.src_ip,
                'dst_ip': packet.dst_ip,
                'packet_id': packet.packet_id,
                **packet.dns_data
            }
            self.dns_events.append(event)
    
    def _add_http_event(self, packet: PacketInfo) -> None:
        """添加HTTP事件"""
        if packet.http_data:
            event = {
                'timestamp': packet.timestamp,
                'src_ip': packet.src_ip,
                'dst_ip': packet.dst_ip,
                'src_port': packet.src_port,
                'dst_port': packet.dst_port,
                'packet_id': packet.packet_id,
                **packet.http_data
            }
            self.http_events.append(event)
    
    def _add_tls_event(self, packet: PacketInfo) -> None:
        """添加TLS事件"""
        if packet.tls_data:
            event = {
                'timestamp': packet.timestamp,
                'src_ip': packet.src_ip,
                'dst_ip': packet.dst_ip,
                'src_port': packet.src_port,
                'dst_port': packet.dst_port,
                'packet_id': packet.packet_id,
                **packet.tls_data
            }
            self.tls_events.append(event)
    
    def flush(self) -> List[FlowRecord]:
        """
        强制完成所有活跃流
        
        Returns:
            所有已完成的流
        """
        for flow in self.active_flows.values():
            self._finalize_flow(flow)
            self.completed_flows.append(flow)
        
        self.active_flows.clear()
        return self.completed_flows
    
    def get_stats(self) -> Dict[str, Any]:
        """获取聚合统计"""
        return {
            'total_packets': self.total_packets,
            'total_bytes': self.total_bytes,
            'active_flows': len(self.active_flows),
            'completed_flows': len(self.completed_flows),
            'dns_events': len(self.dns_events),
            'http_events': len(self.http_events),
            'tls_events': len(self.tls_events)
        }


class FlowAnalyzer:
    """流分析器 - 提供流的统计分析"""
    
    @staticmethod
    def get_top_talkers(flows: List[FlowRecord], top_n: int = 10) -> Dict[str, List]:
        """获取Top通信者"""
        src_ip_bytes = defaultdict(int)
        dst_ip_bytes = defaultdict(int)
        
        for flow in flows:
            src_ip_bytes[flow.src_ip] += flow.total_bytes
            dst_ip_bytes[flow.dst_ip] += flow.total_bytes
        
        top_src = sorted(src_ip_bytes.items(), key=lambda x: x[1], reverse=True)[:top_n]
        top_dst = sorted(dst_ip_bytes.items(), key=lambda x: x[1], reverse=True)[:top_n]
        
        return {
            'top_src_ips': [{'ip': ip, 'bytes': b} for ip, b in top_src],
            'top_dst_ips': [{'ip': ip, 'bytes': b} for ip, b in top_dst]
        }
    
    @staticmethod
    def get_protocol_distribution(flows: List[FlowRecord]) -> Dict[str, int]:
        """获取协议分布"""
        proto_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        distribution = defaultdict(int)
        
        for flow in flows:
            proto_name = proto_map.get(flow.protocol, f'Other({flow.protocol})')
            distribution[proto_name] += flow.total_bytes
        
        return dict(distribution)
    
    @staticmethod
    def get_port_distribution(flows: List[FlowRecord], top_n: int = 10) -> List[Dict]:
        """获取端口分布"""
        port_bytes = defaultdict(int)
        
        for flow in flows:
            port_bytes[flow.dst_port] += flow.total_bytes
        
        top_ports = sorted(port_bytes.items(), key=lambda x: x[1], reverse=True)[:top_n]
        return [{'port': port, 'bytes': b} for port, b in top_ports]
    
    @staticmethod
    def get_connection_timeline(flows: List[FlowRecord], bucket_seconds: int = 60) -> List[Dict]:
        """获取连接时间线"""
        if not flows:
            return []
        
        # 找到时间范围
        min_time = min(f.ts_start for f in flows)
        max_time = max(f.ts_end for f in flows)
        
        # 按时间桶统计
        buckets = defaultdict(lambda: {'connections': 0, 'bytes': 0})
        
        for flow in flows:
            bucket_key = int((flow.ts_start - min_time).total_seconds() / bucket_seconds)
            buckets[bucket_key]['connections'] += 1
            buckets[bucket_key]['bytes'] += flow.total_bytes
        
        # 生成时间线
        timeline = []
        for i in range(max(buckets.keys()) + 1 if buckets else 0):
            timestamp = min_time + timedelta(seconds=i * bucket_seconds)
            data = buckets.get(i, {'connections': 0, 'bytes': 0})
            timeline.append({
                'timestamp': timestamp,
                'connections': data['connections'],
                'bytes': data['bytes']
            })
        
        return timeline
