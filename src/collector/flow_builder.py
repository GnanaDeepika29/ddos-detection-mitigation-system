"""
Flow Builder Module

Converts raw packets into bidirectional network flows (5-tuple aggregation).
Maintains flow state, tracks statistics, and exports flows on timeout.
"""

import time
import heapq
import hashlib
from dataclasses import dataclass, field
from typing import Dict, Optional, Any, Tuple, List
from collections import deque
import logging

logger = logging.getLogger(__name__)


@dataclass
class FlowKey:
    """5-tuple key for flow identification (bidirectional)"""
    ip_src: str
    ip_dst: str
    sport: int
    dport: int
    protocol: int

    _ip_lo: str = field(init=False, repr=False, compare=False)
    _ip_hi: str = field(init=False, repr=False, compare=False)
    _port_lo: int = field(init=False, repr=False, compare=False)
    _port_hi: int = field(init=False, repr=False, compare=False)

    def __post_init__(self):
        # Normalize direction for bidirectional flows
        lo = (self.ip_src, self.sport)
        hi = (self.ip_dst, self.dport)
        if lo > hi:
            lo, hi = hi, lo
        self._ip_lo, self._port_lo = lo
        self._ip_hi, self._port_hi = hi

    def __hash__(self):
        return hash((self._ip_lo, self._port_lo, self._ip_hi, self._port_hi, self.protocol))

    def __eq__(self, other):
        if not isinstance(other, FlowKey):
            return False
        return (self._ip_lo == other._ip_lo and self._port_lo == other._port_lo and
                self._ip_hi == other._ip_hi and self._port_hi == other._port_hi and
                self.protocol == other.protocol)

    def get_reverse(self) -> 'FlowKey':
        """Get the reverse flow key"""
        return FlowKey(
            ip_src=self.ip_dst,
            ip_dst=self.ip_src,
            sport=self.dport,
            dport=self.sport,
            protocol=self.protocol,
        )


@dataclass
class FlowStats:
    """Flow statistics accumulator"""
    packets: int = 0
    bytes: int = 0
    packets_reverse: int = 0
    bytes_reverse: int = 0
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    syn_count: int = 0
    syn_ack_count: int = 0
    rst_count: int = 0
    fin_count: int = 0
    tcp_window_sizes: deque = field(default_factory=lambda: deque(maxlen=100))
    udp_payload_sizes: deque = field(default_factory=lambda: deque(maxlen=100))
    icmp_types: List[int] = field(default_factory=list)
    packet_size_sum: int = 0
    packet_size_sum_reverse: int = 0
    interarrival_times: deque = field(default_factory=lambda: deque(maxlen=1000))
    last_packet_time: float = field(default_factory=time.time)

    def update(self, packet: Dict[str, Any], reverse: bool = False):
        """Update flow statistics with a new packet"""
        now = time.time()
        packet_len = packet.get('length', 0)

        if not reverse:
            self.packets += 1
            self.bytes += packet_len
            self.packet_size_sum += packet_len
        else:
            self.packets_reverse += 1
            self.bytes_reverse += packet_len
            self.packet_size_sum_reverse += packet_len

        # Calculate interarrival time
        interarrival = now - self.last_packet_time
        if 0 < interarrival < 60:  # Sanity check
            self.interarrival_times.append(interarrival)

        self.last_packet_time = now
        self.last_seen = now

        # Protocol-specific updates
        protocol = packet.get('protocol', 0)

        if protocol == 6:  # TCP
            tcp_flags = packet.get('tcp_flags', 0)
            if tcp_flags & 0x02:  # SYN flag
                self.syn_count += 1
            if (tcp_flags & 0x12) == 0x12:  # SYN-ACK
                self.syn_ack_count += 1
            if tcp_flags & 0x04:  # RST flag
                self.rst_count += 1
            if tcp_flags & 0x01:  # FIN flag
                self.fin_count += 1
            if 'tcp_window' in packet:
                self.tcp_window_sizes.append(packet['tcp_window'])
        elif protocol == 17:  # UDP
            if 'udp_len' in packet:
                self.udp_payload_sizes.append(packet['udp_len'])
        elif protocol == 1:  # ICMP
            if 'icmp_type' in packet:
                self.icmp_types.append(packet['icmp_type'])

    @property
    def duration(self) -> float:
        """Flow duration in seconds"""
        return self.last_seen - self.first_seen

    @property
    def packets_per_second(self) -> float:
        """Packets per second (forward direction)"""
        return self.packets / self.duration if self.duration > 0 else 0

    @property
    def bytes_per_second(self) -> float:
        """Bytes per second (forward direction)"""
        return self.bytes / self.duration if self.duration > 0 else 0

    @property
    def avg_packet_size(self) -> float:
        """Average packet size (forward direction)"""
        return self.packet_size_sum / self.packets if self.packets > 0 else 0

    @property
    def tcp_syn_ratio(self) -> float:
        """Ratio of SYN to SYN-ACK packets"""
        return self.syn_count / self.syn_ack_count if self.syn_ack_count > 0 else 0

    @property
    def total_packets(self) -> int:
        """Total packets in both directions"""
        return self.packets + self.packets_reverse

    @property
    def total_bytes(self) -> int:
        """Total bytes in both directions"""
        return self.bytes + self.bytes_reverse


@dataclass
class Flow:
    """Complete flow object with key and statistics"""
    key: FlowKey
    stats: FlowStats
    features: Dict[str, Any] = field(default_factory=dict)
    application_protocol: Optional[str] = None
    vlan_id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert flow to dictionary for serialization"""
        iat = list(self.stats.interarrival_times)
        tcp_wins = list(self.stats.tcp_window_sizes)
        udp_sizes = list(self.stats.udp_payload_sizes)

        return {
            'flow_id': self.get_flow_id(),
            'ip_src': self.key.ip_src,
            'ip_dst': self.key.ip_dst,
            'sport': self.key.sport,
            'dport': self.key.dport,
            'protocol': self.key.protocol,
            'first_seen': self.stats.first_seen,
            'last_seen': self.stats.last_seen,
            'duration': self.stats.duration,
            'packets': self.stats.packets,
            'bytes': self.stats.bytes,
            'packets_reverse': self.stats.packets_reverse,
            'bytes_reverse': self.stats.bytes_reverse,
            'total_packets': self.stats.total_packets,
            'total_bytes': self.stats.total_bytes,
            'packets_per_sec': self.stats.packets_per_second,
            'bytes_per_sec': self.stats.bytes_per_second,
            'avg_packet_size': self.stats.avg_packet_size,
            'tcp_syn_count': self.stats.syn_count,
            'tcp_syn_ack_count': self.stats.syn_ack_count,
            'tcp_rst_count': self.stats.rst_count,
            'tcp_fin_count': self.stats.fin_count,
            'tcp_syn_ratio': self.stats.tcp_syn_ratio,
            'tcp_window_avg': sum(tcp_wins) / len(tcp_wins) if tcp_wins else 0,
            'tcp_window_std': self._calculate_std(tcp_wins),
            'udp_payload_avg': sum(udp_sizes) / len(udp_sizes) if udp_sizes else 0,
            'udp_payload_std': self._calculate_std(udp_sizes),
            'interarrival_mean': sum(iat) / len(iat) if iat else 0,
            'interarrival_std': self._calculate_std(iat),
            'application_protocol': self.application_protocol,
            'vlan_id': self.vlan_id,
        }

    def _calculate_std(self, values: List[float]) -> float:
        """Calculate standard deviation of a list of values"""
        if not values:
            return 0
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return variance ** 0.5

    def get_flow_id(self) -> str:
        """Generate a unique flow ID"""
        flow_string = (f"{self.key._ip_lo}|{self.key._port_lo}|"
                       f"{self.key._ip_hi}|{self.key._port_hi}|{self.key.protocol}")
        return hashlib.sha256(flow_string.encode()).hexdigest()[:16]

    def is_complete(self) -> bool:
        """Check if flow is complete (TCP termination)"""
        if self.key.protocol == 6:  # TCP
            return self.stats.fin_count > 0 or self.stats.rst_count > 0
        return False


class FlowBuilder:
    """Builds and manages network flows from packets"""
    
    def __init__(self, idle_timeout: int = 30, active_timeout: int = 60, max_flows: int = 100000):
        self.idle_timeout = idle_timeout
        self.active_timeout = active_timeout
        self.max_flows = max_flows
        self.flows: Dict[FlowKey, Flow] = {}
        self.exported_flows: deque = deque(maxlen=10000)
        self.last_processed_flow: Optional[Flow] = None
        self._cleanup_interval = min(self.idle_timeout, 10)
        self.last_cleanup = time.time()

        logger.info(f"FlowBuilder initialized: idle_timeout={idle_timeout}s, "
                    f"active_timeout={active_timeout}s, max_flows={max_flows}")

    def process_packet(self, packet: Dict[str, Any]) -> Optional[Flow]:
        """
        Process a packet and update/create flow.
        Returns exported flow if flow completed, None otherwise.
        """
        try:
            ip_src = packet.get('ip_src')
            ip_dst = packet.get('ip_dst')
            sport = packet.get('sport', 0)
            dport = packet.get('dport', 0)
            protocol = packet.get('protocol', 0)

            if not all([ip_src, ip_dst]):
                return None

            # Create flow key
            key = FlowKey(ip_src, ip_dst, sport, dport, protocol)
            flow = self.flows.get(key)

            # Determine if packet is reverse direction
            reverse = False
            if not flow:
                # Try reverse key
                reverse_key = key.get_reverse()
                flow = self.flows.get(reverse_key)
                if flow:
                    reverse = True
                    key = reverse_key

            # Create new flow if not exists
            if not flow:
                flow = Flow(key=key, stats=FlowStats())
                self.flows[key] = flow
                if len(self.flows) > self.max_flows:
                    self._evict_oldest_flows()
            else:
                # For existing flows, determine direction based on actual packet
                if not reverse and (ip_src != key.ip_src or sport != key.sport):
                    reverse = True

            # Update flow statistics
            flow.stats.update(packet, reverse)
            self.last_processed_flow = flow

            # Periodic cleanup
            if time.time() - self.last_cleanup > self._cleanup_interval:
                self._cleanup_timeout_flows()
                self.last_cleanup = time.time()

            # Check if flow should be exported
            if self._should_export(flow):
                exported = self._export_flow(key)
                self.last_processed_flow = exported
                return exported

            return None

        except Exception as e:
            logger.error(f"Error processing packet: {e}")
            return None

    def _should_export(self, flow: Flow) -> bool:
        """Determine if flow should be exported"""
        now = time.time()
        
        # Active timeout reached
        if now - flow.stats.first_seen > self.active_timeout:
            return True
            
        # Flow completed (TCP termination)
        if flow.is_complete():
            return True
            
        return False

    def _export_flow(self, key: FlowKey) -> Optional[Flow]:
        """Export and remove a flow"""
        flow = self.flows.pop(key, None)
        if flow:
            self.exported_flows.append(flow)
            logger.debug(f"Exported flow {flow.get_flow_id()}: "
                        f"{flow.stats.total_packets} packets, "
                        f"{flow.stats.duration:.2f}s duration")
            return flow
        return None

    def _cleanup_timeout_flows(self):
        """Remove flows that have exceeded idle timeout"""
        now = time.time()
        to_remove = [key for key, flow in self.flows.items()
                     if now - flow.stats.last_seen > self.idle_timeout]

        for key in to_remove:
            self._export_flow(key)

        if to_remove:
            logger.debug(f"Cleaned up {len(to_remove)} idle flows")

    def _evict_oldest_flows(self):
        """Evict oldest flows when max_flows limit is reached"""
        if not self.flows:
            return
            
        evict_count = max(1, int(self.max_flows * 0.1))
        oldest = heapq.nsmallest(evict_count, self.flows.items(), 
                                key=lambda x: x[1].stats.last_seen)

        for key, _ in oldest:
            self._export_flow(key)

        logger.warning(f"Evicted {evict_count} oldest flows due to max limit")

    def get_stats(self) -> Dict[str, Any]:
        """Get flow builder statistics"""
        return {
            'active_flows': len(self.flows),
            'exported_flows': len(self.exported_flows),
            'max_flows': self.max_flows,
            'idle_timeout': self.idle_timeout,
            'active_timeout': self.active_timeout,
        }

    def flush_all(self) -> List[Flow]:
        """Export all active flows"""
        flows = []
        for key in list(self.flows.keys()):
            flow = self._export_flow(key)
            if flow:
                flows.append(flow)
        logger.info(f"Flushed {len(flows)} active flows")
        return flows
