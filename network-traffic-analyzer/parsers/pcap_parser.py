"""
PCAP解析器 - 使用dpkt进行高效解析
"""
import dpkt
import socket
import struct
import hashlib
from datetime import datetime
from typing import Generator, Dict, Any, Optional, Tuple, List
from dataclasses import dataclass, field
import math
from collections import defaultdict


@dataclass
class PacketInfo:
    """解析后的数据包信息"""
    timestamp: datetime
    packet_id: int
    
    # 链路层
    eth_src: Optional[str] = None
    eth_dst: Optional[str] = None
    eth_type: int = 0
    
    # 网络层
    src_ip: str = ""
    dst_ip: str = ""
    ip_version: int = 4
    ip_proto: int = 0
    ip_len: int = 0
    ip_ttl: int = 0
    
    # 传输层
    src_port: int = 0
    dst_port: int = 0
    
    # TCP特定
    tcp_flags: int = 0
    tcp_seq: int = 0
    tcp_ack: int = 0
    tcp_window: int = 0
    
    # 应用层
    payload: bytes = field(default_factory=bytes)
    payload_len: int = 0
    
    # 协议识别
    app_protocol: Optional[str] = None
    
    # DNS解析结果
    dns_data: Optional[Dict] = None
    
    # HTTP解析结果
    http_data: Optional[Dict] = None
    
    # TLS解析结果
    tls_data: Optional[Dict] = None


def mac_to_str(mac: bytes) -> str:
    """将MAC地址字节转换为字符串"""
    return ':'.join('%02x' % b for b in mac)


def ip_to_str(ip: bytes) -> str:
    """将IP地址字节转换为字符串"""
    try:
        if len(ip) == 4:
            return socket.inet_ntop(socket.AF_INET, ip)
        elif len(ip) == 16:
            return socket.inet_ntop(socket.AF_INET6, ip)
    except:
        pass
    return ""


def calculate_entropy(data: str) -> float:
    """计算字符串的Shannon熵"""
    if not data:
        return 0.0
    
    freq = defaultdict(int)
    for char in data:
        freq[char] += 1
    
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    
    return entropy


def get_tcp_flags_str(flags: int) -> str:
    """获取TCP标志的字符串表示"""
    flag_names = []
    if flags & dpkt.tcp.TH_FIN:
        flag_names.append('FIN')
    if flags & dpkt.tcp.TH_SYN:
        flag_names.append('SYN')
    if flags & dpkt.tcp.TH_RST:
        flag_names.append('RST')
    if flags & dpkt.tcp.TH_PUSH:
        flag_names.append('PSH')
    if flags & dpkt.tcp.TH_ACK:
        flag_names.append('ACK')
    if flags & dpkt.tcp.TH_URG:
        flag_names.append('URG')
    return '|'.join(flag_names) if flag_names else ''


class DnsParser:
    """DNS协议解析器"""
    
    QUERY_TYPES = {
        1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR',
        15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 35: 'NAPTR',
        255: 'ANY', 257: 'CAA'
    }
    
    RESPONSE_CODES = {
        0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN',
        4: 'NOTIMP', 5: 'REFUSED', 6: 'YXDOMAIN', 7: 'YXRRSET',
        8: 'NXRRSET', 9: 'NOTAUTH', 10: 'NOTZONE'
    }
    
    @classmethod
    def parse(cls, data: bytes) -> Optional[Dict]:
        """解析DNS数据"""
        try:
            dns = dpkt.dns.DNS(data)
            
            result = {
                'transaction_id': dns.id,
                'is_response': bool(dns.qr),
                'opcode': dns.opcode,
                'response_code': cls.RESPONSE_CODES.get(dns.rcode, str(dns.rcode)),
                'query_name': '',
                'query_type': '',
                'answers': []
            }
            
            # 解析查询
            if dns.qd:
                qd = dns.qd[0]
                result['query_name'] = qd.name
                result['query_type'] = cls.QUERY_TYPES.get(qd.type, str(qd.type))
                
                # 计算域名特征
                result['qname_length'] = len(qd.name)
                result['subdomain_count'] = qd.name.count('.') + 1 if qd.name else 0
                result['entropy'] = calculate_entropy(qd.name.split('.')[0] if '.' in qd.name else qd.name)
            
            # 解析响应
            if dns.an:
                for rr in dns.an:
                    answer = {
                        'name': rr.name,
                        'type': cls.QUERY_TYPES.get(rr.type, str(rr.type)),
                        'ttl': rr.ttl
                    }
                    
                    # 解析响应数据
                    if rr.type == dpkt.dns.DNS_A and len(rr.rdata) == 4:
                        answer['data'] = socket.inet_ntop(socket.AF_INET, rr.rdata)
                    elif rr.type == dpkt.dns.DNS_AAAA and len(rr.rdata) == 16:
                        answer['data'] = socket.inet_ntop(socket.AF_INET6, rr.rdata)
                    elif rr.type in (dpkt.dns.DNS_CNAME, dpkt.dns.DNS_NS, dpkt.dns.DNS_PTR):
                        answer['data'] = rr.rdata.decode('utf-8', errors='ignore') if isinstance(rr.rdata, bytes) else str(rr.rdata)
                    elif rr.type == dpkt.dns.DNS_TXT:
                        answer['data'] = rr.rdata.decode('utf-8', errors='ignore') if isinstance(rr.rdata, bytes) else str(rr.rdata)
                    elif rr.type == dpkt.dns.DNS_MX:
                        answer['data'] = str(rr.rdata)
                    else:
                        answer['data'] = rr.rdata.hex() if isinstance(rr.rdata, bytes) else str(rr.rdata)
                    
                    result['answers'].append(answer)
            
            return result
            
        except Exception as e:
            return None


class HttpParser:
    """HTTP协议解析器"""
    
    @classmethod
    def parse_request(cls, data: bytes) -> Optional[Dict]:
        """解析HTTP请求"""
        try:
            request = dpkt.http.Request(data)
            
            result = {
                'type': 'request',
                'method': request.method,
                'uri': request.uri,
                'version': request.version,
                'headers': dict(request.headers),
                'host': request.headers.get('host', ''),
                'user_agent': request.headers.get('user-agent', ''),
                'referer': request.headers.get('referer', ''),
                'content_type': request.headers.get('content-type', ''),
                'content_length': int(request.headers.get('content-length', 0)),
                'cookie': request.headers.get('cookie', '')
            }
            
            return result
            
        except Exception:
            return None
    
    @classmethod
    def parse_response(cls, data: bytes) -> Optional[Dict]:
        """解析HTTP响应"""
        try:
            response = dpkt.http.Response(data)
            
            result = {
                'type': 'response',
                'status_code': int(response.status),
                'reason': response.reason,
                'version': response.version,
                'headers': dict(response.headers),
                'content_type': response.headers.get('content-type', ''),
                'content_length': int(response.headers.get('content-length', 0)),
                'server': response.headers.get('server', '')
            }
            
            return result
            
        except Exception:
            return None
    
    @classmethod
    def parse(cls, data: bytes) -> Optional[Dict]:
        """尝试解析HTTP数据"""
        # 先尝试解析为请求
        result = cls.parse_request(data)
        if result:
            return result
        
        # 再尝试解析为响应
        return cls.parse_response(data)


class TlsParser:
    """TLS协议解析器"""
    
    TLS_VERSIONS = {
        0x0301: 'TLS 1.0',
        0x0302: 'TLS 1.1',
        0x0303: 'TLS 1.2',
        0x0304: 'TLS 1.3'
    }
    
    @classmethod
    def parse_client_hello(cls, data: bytes) -> Optional[Dict]:
        """解析TLS Client Hello"""
        try:
            if len(data) < 6:
                return None
            
            # TLS记录层
            content_type = data[0]
            if content_type != 22:  # Handshake
                return None
            
            version = struct.unpack('!H', data[1:3])[0]
            record_length = struct.unpack('!H', data[3:5])[0]
            
            if len(data) < 5 + record_length:
                return None
            
            # Handshake层
            handshake_type = data[5]
            if handshake_type != 1:  # Client Hello
                return None
            
            result = {
                'tls_version': cls.TLS_VERSIONS.get(version, f'0x{version:04x}'),
                'sni': None,
                'cipher_suites': [],
                'extensions': [],
                'ja3_hash': None
            }
            
            pos = 9  # 跳过handshake头
            
            # Client Version
            if pos + 2 > len(data):
                return result
            client_version = struct.unpack('!H', data[pos:pos+2])[0]
            pos += 2
            
            # Random (32 bytes)
            pos += 32
            
            # Session ID
            if pos + 1 > len(data):
                return result
            session_id_len = data[pos]
            pos += 1 + session_id_len
            
            # Cipher Suites
            if pos + 2 > len(data):
                return result
            cipher_suites_len = struct.unpack('!H', data[pos:pos+2])[0]
            pos += 2
            
            cipher_suites = []
            for i in range(0, cipher_suites_len, 2):
                if pos + 2 > len(data):
                    break
                cs = struct.unpack('!H', data[pos:pos+2])[0]
                cipher_suites.append(cs)
                pos += 2
            result['cipher_suites'] = cipher_suites
            
            # Compression Methods
            if pos + 1 > len(data):
                return result
            comp_methods_len = data[pos]
            pos += 1 + comp_methods_len
            
            # Extensions
            if pos + 2 > len(data):
                return result
            extensions_len = struct.unpack('!H', data[pos:pos+2])[0]
            pos += 2
            
            extensions_end = pos + extensions_len
            extensions = []
            
            while pos + 4 <= extensions_end and pos + 4 <= len(data):
                ext_type = struct.unpack('!H', data[pos:pos+2])[0]
                ext_len = struct.unpack('!H', data[pos+2:pos+4])[0]
                pos += 4
                
                extensions.append(ext_type)
                
                # SNI extension (type 0)
                if ext_type == 0 and ext_len > 0:
                    if pos + 5 <= len(data):
                        sni_list_len = struct.unpack('!H', data[pos:pos+2])[0]
                        sni_type = data[pos+2]
                        sni_len = struct.unpack('!H', data[pos+3:pos+5])[0]
                        
                        if sni_type == 0 and pos + 5 + sni_len <= len(data):
                            result['sni'] = data[pos+5:pos+5+sni_len].decode('utf-8', errors='ignore')
                
                pos += ext_len
            
            result['extensions'] = extensions
            
            # 计算JA3指纹
            ja3_string = f"{client_version},{'-'.join(map(str, cipher_suites))},{'-'.join(map(str, extensions))}"
            result['ja3_hash'] = hashlib.md5(ja3_string.encode()).hexdigest()
            
            return result
            
        except Exception:
            return None
    
    @classmethod
    def parse(cls, data: bytes) -> Optional[Dict]:
        """解析TLS数据"""
        return cls.parse_client_hello(data)


class PcapParser:
    """PCAP文件解析器"""
    
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.packet_count = 0
    
    def parse(self) -> Generator[PacketInfo, None, None]:
        """解析PCAP文件，生成数据包信息"""
        
        with open(self.filepath, 'rb') as f:
            try:
                pcap = dpkt.pcap.Reader(f)
            except ValueError:
                # 尝试pcapng格式
                f.seek(0)
                try:
                    pcap = dpkt.pcapng.Reader(f)
                except:
                    raise ValueError(f"无法解析文件: {self.filepath}")
            
            for timestamp, buf in pcap:
                self.packet_count += 1
                packet_info = self._parse_packet(timestamp, buf, self.packet_count)
                if packet_info:
                    yield packet_info
    
    def _parse_packet(self, timestamp: float, buf: bytes, packet_id: int) -> Optional[PacketInfo]:
        """解析单个数据包"""
        try:
            info = PacketInfo(
                timestamp=datetime.fromtimestamp(timestamp),
                packet_id=packet_id
            )
            
            # 解析以太网帧
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except:
                # 可能是原始IP
                try:
                    ip = dpkt.ip.IP(buf)
                    return self._parse_ip(info, ip)
                except:
                    return None
            
            info.eth_src = mac_to_str(eth.src)
            info.eth_dst = mac_to_str(eth.dst)
            info.eth_type = eth.type
            
            # 解析IP层
            if isinstance(eth.data, dpkt.ip.IP):
                return self._parse_ip(info, eth.data)
            elif isinstance(eth.data, dpkt.ip6.IP6):
                return self._parse_ip6(info, eth.data)
            
            return info
            
        except Exception:
            return None
    
    def _parse_ip(self, info: PacketInfo, ip: dpkt.ip.IP) -> PacketInfo:
        """解析IPv4"""
        info.ip_version = 4
        info.src_ip = ip_to_str(ip.src)
        info.dst_ip = ip_to_str(ip.dst)
        info.ip_proto = ip.p
        info.ip_len = ip.len
        info.ip_ttl = ip.ttl
        
        # 解析传输层
        if ip.p == dpkt.ip.IP_PROTO_TCP:
            self._parse_tcp(info, ip.data)
        elif ip.p == dpkt.ip.IP_PROTO_UDP:
            self._parse_udp(info, ip.data)
        elif ip.p == dpkt.ip.IP_PROTO_ICMP:
            info.app_protocol = 'ICMP'
        
        return info
    
    def _parse_ip6(self, info: PacketInfo, ip6: dpkt.ip6.IP6) -> PacketInfo:
        """解析IPv6"""
        info.ip_version = 6
        info.src_ip = ip_to_str(ip6.src)
        info.dst_ip = ip_to_str(ip6.dst)
        info.ip_proto = ip6.nxt
        info.ip_len = ip6.plen
        
        # 解析传输层
        if ip6.nxt == dpkt.ip.IP_PROTO_TCP:
            self._parse_tcp(info, ip6.data)
        elif ip6.nxt == dpkt.ip.IP_PROTO_UDP:
            self._parse_udp(info, ip6.data)
        
        return info
    
    def _parse_tcp(self, info: PacketInfo, tcp) -> None:
        """解析TCP"""
        if not isinstance(tcp, dpkt.tcp.TCP):
            return
        
        info.src_port = tcp.sport
        info.dst_port = tcp.dport
        info.tcp_flags = tcp.flags
        info.tcp_seq = tcp.seq
        info.tcp_ack = tcp.ack
        info.tcp_window = tcp.win
        info.payload = bytes(tcp.data) if tcp.data else b''
        info.payload_len = len(info.payload)
        
        # 应用层协议识别
        if info.payload_len > 0:
            self._identify_app_protocol(info)
    
    def _parse_udp(self, info: PacketInfo, udp) -> None:
        """解析UDP"""
        if not isinstance(udp, dpkt.udp.UDP):
            return
        
        info.src_port = udp.sport
        info.dst_port = udp.dport
        info.payload = bytes(udp.data) if udp.data else b''
        info.payload_len = len(info.payload)
        
        # DNS检测
        if info.src_port == 53 or info.dst_port == 53:
            info.app_protocol = 'DNS'
            if info.payload_len > 0:
                info.dns_data = DnsParser.parse(info.payload)
    
    def _identify_app_protocol(self, info: PacketInfo) -> None:
        """识别应用层协议"""
        payload = info.payload
        
        # HTTP检测
        if info.dst_port == 80 or info.src_port == 80:
            http_data = HttpParser.parse(payload)
            if http_data:
                info.app_protocol = 'HTTP'
                info.http_data = http_data
                return
        
        # HTTPS/TLS检测
        if info.dst_port == 443 or info.src_port == 443 or (len(payload) > 0 and payload[0] == 0x16):
            tls_data = TlsParser.parse(payload)
            if tls_data:
                info.app_protocol = 'TLS'
                info.tls_data = tls_data
                return
        
        # DNS over TCP
        if info.dst_port == 53 or info.src_port == 53:
            info.app_protocol = 'DNS'
            if len(payload) > 2:
                # TCP DNS有2字节长度前缀
                info.dns_data = DnsParser.parse(payload[2:])
            return
        
        # SSH检测
        if info.dst_port == 22 or info.src_port == 22:
            info.app_protocol = 'SSH'
            return
        
        # 尝试HTTP检测（非标准端口）
        if payload.startswith(b'GET ') or payload.startswith(b'POST ') or \
           payload.startswith(b'HTTP/') or payload.startswith(b'PUT ') or \
           payload.startswith(b'DELETE ') or payload.startswith(b'HEAD '):
            http_data = HttpParser.parse(payload)
            if http_data:
                info.app_protocol = 'HTTP'
                info.http_data = http_data
                return


def get_five_tuple(packet: PacketInfo) -> Tuple[str, str, int, int, int]:
    """获取数据包的五元组"""
    return (packet.src_ip, packet.dst_ip, packet.src_port, packet.dst_port, packet.ip_proto)


def get_normalized_five_tuple(packet: PacketInfo) -> Tuple[str, str, int, int, int, bool]:
    """
    获取归一化的五元组（用于双向流匹配）
    返回: (ip1, ip2, port1, port2, proto, is_original_direction)
    """
    t1 = (packet.src_ip, packet.dst_ip, packet.src_port, packet.dst_port)
    t2 = (packet.dst_ip, packet.src_ip, packet.dst_port, packet.src_port)
    
    if t1 < t2:
        return (packet.src_ip, packet.dst_ip, packet.src_port, packet.dst_port, packet.ip_proto, True)
    else:
        return (packet.dst_ip, packet.src_ip, packet.dst_port, packet.src_port, packet.ip_proto, False)
