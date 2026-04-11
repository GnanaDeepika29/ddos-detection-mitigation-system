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

    def __post_init__(self) -> None:
        # Normalise direction so (A→B) and (B→A) hash to the same key.
        lo: Tuple[str, int] = (self.ip_src, self.sport)
        hi: Tuple[str, int] = (self.ip_dst, self.dport)
        if lo > hi:
            lo, hi = hi, lo
        self._ip_lo, self._port_lo = lo
        self._ip_hi, self._port_hi = hi

    def __hash__(self) -> int:
        return hash((self._ip_lo, self._port_lo, self._ip_hi, self._port_hi, self.protocol))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, FlowKey):
            return False
        return (
            self._ip_lo == other._ip_lo
            and self._port_lo == other._port_lo
            and self._ip_hi == other._ip_hi
            and self._port_hi == other._port_hi
            and self.protocol == other.protocol
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

    # FIX BUG-12: Was initialised to time.time() at field creation, so the
    # very first interarrival was measured from object-creation time rather
    # than from the first real packet — producing a near-zero or garbage value.
    # Using None as sentinel lets update() skip the first observation.
    last_packet_time: Optional[float] = None

    def update(self, packet: Dict[str, Any], reverse: bool = False) -> None:
        """Update flow statistics with a new packet."""
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

        # FIX BUG-12 (cont.): Skip the first interarrival; only record from
        # the second packet onward when last_packet_time is known.
        if self.last_packet_time is not None:
            interarrival = now - self.last_packet_time
            if 0 < interarrival < 60:   # Sanity-check against stale timestamps
                self.interarrival_times.append(interarrival)

        self.last_packet_time = now
        self.last_seen = now

        # Protocol-specific updates
        protocol = packet.get('protocol', 0)

        if protocol == 6:  # TCP
            tcp_flags = packet.get('tcp_flags', 0)
            if tcp_flags & 0x02:            # SYN
                self.syn_count += 1
            if (tcp_flags & 0x12) == 0x12:  # SYN-ACK
                self.syn_ack_count += 1
            if tcp_flags & 0x04:            # RST
                self.rst_count += 1
            if tcp_flags & 0x01:            # FIN
                self.fin_count += 1
            if 'tcp_window' in packet:
                self.tcp_window_sizes.append(packet['tcp_window'])
        elif protocol == 17:  # UDP
            if 'udp_len' in packet:
                self.udp_payload_sizes.append(packet['udp_len'])
        elif protocol == 1:   # ICMP
            if 'icmp_type' in packet:
                self.icmp_types.append(packet['icmp_type'])

    # ------------------------------------------------------------------
    # Derived properties
    # ------------------------------------------------------------------

    @property
    def duration(self) -> float:
        """Flow duration in seconds."""
        return self.last_seen - self.first_seen

    @property
    def packets_per_second(self) -> float:
        """Forward-direction packets per second."""
        return self.packets / self.duration if self.duration > 0 else 0.0

    @property
    def bytes_per_second(self) -> float:
        """Forward-direction bytes per second."""
        return self.bytes / self.duration if self.duration > 0 else 0.0

    @property
    def avg_packet_size(self) -> float:
        """Average packet size (forward direction)."""
        return self.packet_size_sum / self.packets if self.packets > 0 else 0.0

    @property
    def tcp_syn_ratio(self) -> float:
        """
        Fraction of total TCP packets that are SYNs.

        FIX BUG-8: The original formula was syn_count / syn_ack_count which:
          • Returned 0 when syn_ack_count == 0 — incorrect: a pure SYN flood
            has NO SYN-ACKs, so the ratio should be 1.0, not 0.
          • Was the wrong metric: thresholds.yaml and prod.yaml both define
            syn_flood_syn_ratio as "fraction of packets that are SYN" (i.e.
            how dominant SYNs are in the flow), not the SYN:SYN-ACK ratio.

        Correct formula: syn_packets / total_packets.
        """
        total = self.total_packets
        return self.syn_count / total if total > 0 else 0.0

    @property
    def total_packets(self) -> int:
        """Total packets in both directions."""
        return self.packets + self.packets_reverse

    @property
    def total_bytes(self) -> int:
        """Total bytes in both directions."""
        return self.bytes + self.bytes_reverse


@dataclass
class Flow:
    """Complete flow object with key and statistics."""
    key: FlowKey
    stats: FlowStats
    features: Dict[str, Any] = field(default_factory=dict)
    application_protocol: Optional[str] = None
    vlan_id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert flow to a serialisable dictionary."""
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
            # BUG-8 fix: now correctly returns SYN / total_packets
            'tcp_syn_ratio': self.stats.tcp_syn_ratio,
            'tcp_window_avg': sum(tcp_wins) / len(tcp_wins) if tcp_wins else 0.0,
            'tcp_window_std': self._calculate_std(tcp_wins),
            'udp_payload_avg': sum(udp_sizes) / len(udp_sizes) if udp_sizes else 0.0,
            'udp_payload_std': self._calculate_std(udp_sizes),
            'interarrival_mean': sum(iat) / len(iat) if iat else 0.0,
            'interarrival_std': self._calculate_std(iat),
            'application_protocol': self.application_protocol,
            'vlan_id': self.vlan_id,
        }

    @staticmethod
    def _calculate_std(values: List[float]) -> float:
        """
        Calculates population standard deviation using Welford's online algorithm
        for better numerical stability.
        """
        if not values:
            return 0.0
        
        n = 0
        mean = 0.0
        m2 = 0.0

        for x in values:
            n += 1
            delta = x - mean
            mean += delta / n
            delta2 = x - mean
            m2 += delta * delta2

        if n < 2:
            return 0.0

        variance = m2 / n
        return variance ** 0.5

    def get_flow_id(self) -> str:
        """Generate a short, stable, unique flow ID (hex digest)."""
        flow_string = (
            f"{self.key._ip_lo}|{self.key._port_lo}|"
            f"{self.key._ip_hi}|{self.key._port_hi}|{self.key.protocol}"
        )
        return hashlib.sha256(flow_string.encode()).hexdigest()[:16]

    def is_complete(self) -> bool:
        """Return True if the TCP flow has been terminated (FIN or RST)."""
        if self.key.protocol == 6:
            return self.stats.fin_count > 0 or self.stats.rst_count > 0
        return False


class FlowBuilder:
    """Builds and manages bidirectional network flows from individual packets."""

    def __init__(
        self,
        idle_timeout: int = 30,
        active_timeout: int = 60,
        max_flows: int = 100_000,
    ) -> None:
        self.idle_timeout = idle_timeout
        self.active_timeout = active_timeout
        self.max_flows = max_flows
        self.flows: Dict[FlowKey, Flow] = {}
        self._flow_lru: List[Tuple[float, FlowKey]] = []
        self.exported_flows: deque = deque(maxlen=10_000)
        self.last_processed_flow: Optional[Flow] = None
        self._cleanup_interval = min(self.idle_timeout, 10)
        self.last_cleanup = time.time()

        logger.info(
            f"FlowBuilder initialised: idle_timeout={idle_timeout}s, "
            f"active_timeout={active_timeout}s, max_flows={max_flows}"
        )

    def process_packet(self, packet: Dict[str, Any]) -> Optional[Flow]:
        """
        Process a packet and update / create its flow.
        Returns the exported Flow if the flow completed, None otherwise.
        """
        try:
            ip_src = packet.get('ip_src')
            ip_dst = packet.get('ip_dst')
            sport = packet.get('sport', 0)
            dport = packet.get('dport', 0)
            protocol = packet.get('protocol', 0)

            if not (ip_src and ip_dst):
                return None

            key = FlowKey(ip_src, ip_dst, sport, dport, protocol)

            # FIX BUG-9: The original direction logic was convoluted and
            # contained unreachable code.  Simplified version:
            #   1. Look up the canonical key directly.
            #   2. If not found, check whether an existing flow matches the
            #      *reverse* direction (the same normalised key, since FlowKey
            #      normalises internally).
            #   3. Determine `reverse` by comparing the packet's src/sport
            #      against the stored flow key's ip_src/sport.
            flow = self.flows.get(key)
            if flow is None:
                # FlowKey normalises bidirectional flows, so looking up the
                # reverse key yields the same normalised key — just create a
                # new flow entry under the canonical key.
                flow = Flow(key=key, stats=FlowStats())
                self.flows[key] = flow
                if len(self.flows) > self.max_flows:
                    self._evict_oldest_flows()

                # Add to LRU tracking
                heapq.heappush(self._flow_lru, (flow.stats.last_seen, key))

            # Determine packet direction relative to the stored flow key.
            reverse = (ip_src != flow.key.ip_src or sport != flow.key.sport)

            flow.stats.update(packet, reverse)

            # Update LRU tracking
            heapq.heappush(self._flow_lru, (flow.stats.last_seen, key))

            self.last_processed_flow = flow

            # Periodic idle-flow cleanup
            now = time.time()
            if now - self.last_cleanup > self._cleanup_interval:
                self._cleanup_timeout_flows()
                self.last_cleanup = now

            # Export on active-timeout or TCP termination
            if self._should_export(flow):
                exported = self._export_flow(key)
                self.last_processed_flow = exported
                return exported

            return None

        except Exception as exc:
            logger.error(f"Error processing packet in FlowBuilder: {exc}")
            return None

    def _should_export(self, flow: Flow) -> bool:
        """Return True if the flow should be exported now."""
        if time.time() - flow.stats.first_seen > self.active_timeout:
            return True
        if flow.is_complete():
            return True
        return False

    def _export_flow(self, key: FlowKey) -> Optional[Flow]:
        """Remove flow from the active table and append to exported queue."""
        flow = self.flows.pop(key, None)
        if flow:
            self.exported_flows.append(flow)
            logger.debug(
                f"Exported flow {flow.get_flow_id()}: "
                f"{flow.stats.total_packets} pkts, "
                f"{flow.stats.duration:.2f}s"
            )
        return flow

    def _cleanup_timeout_flows(self) -> None:
        """Export flows that have exceeded the idle timeout."""
        now = time.time()
        stale = [
            key for key, flow in self.flows.items()
            if now - flow.stats.last_seen > self.idle_timeout
        ]
        for key in stale:
            self._export_flow(key)
        if stale:
            logger.debug(f"Cleaned up {len(stale)} idle flows")

    def _evict_oldest_flows(self) -> None:
        """LRU-evict 10% of flows when the max-flows limit is breached."""
        if not self._flow_lru:
            return
        
        evict_count = max(1, int(self.max_flows * 0.1))
        
        # Prune the LRU heap to remove stale entries
        while self._flow_lru and self._flow_lru[0][1] not in self.flows:
            heapq.heappop(self._flow_lru)

        for _ in range(evict_count):
            if not self._flow_lru:
                break
            _, key = heapq.heappop(self._flow_lru)
            self._export_flow(key)
            
        logger.warning(f"Evicted {evict_count} oldest flows (max_flows limit reached)")

    def get_stats(self) -> Dict[str, Any]:
        """Return summary statistics for the flow builder."""
        return {
            'active_flows': len(self.flows),
            'exported_flows': len(self.exported_flows),
            'max_flows': self.max_flows,
            'idle_timeout': self.idle_timeout,
            'active_timeout': self.active_timeout,
        }

    def flush_all(self) -> List[Flow]:
        """Export every active flow (e.g. on shutdown)."""
        flows = []
        for key in list(self.flows.keys()):
            flow = self._export_flow(key)
            if flow:
                flows.append(flow)
        logger.info(f"Flushed {len(flows)} active flows")
        return flows