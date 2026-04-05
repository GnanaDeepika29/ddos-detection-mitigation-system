"""
Live Packet Capture Module

Captures raw packets from network interfaces using Scapy or libpcap,
performs basic filtering, and forwards packets to FlowBuilder.
"""

import asyncio
import logging
import signal
import time
from dataclasses import dataclass, field
from typing import Optional, Callable, List, Dict, Any
from collections import deque

# Import scapy modules with error handling
try:
    import scapy.all as scapy
    from scapy.packet import Packet
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logging.warning("Scapy not available. Packet capture will be disabled.")

logger = logging.getLogger(__name__)


@dataclass
class PacketCaptureConfig:
    """Configuration for packet capture"""
    interface: str = "eth0"
    promiscuous: bool = True
    snaplen: int = 1518  # Maximum bytes per packet
    timeout: int = 1  # Packet capture timeout (seconds)
    filter_bpf: str = ""  # BPF filter (e.g., "tcp or udp")
    buffer_size_mb: int = 64  # Capture buffer size
    max_packets_per_second: int = 100000  # Throttle if exceeded
    enable_stats: bool = True
    capture_raw_packets: bool = False  
    capture_http_headers: bool = False
    capture_dns_queries: bool = False

    # Performance settings
    use_pf_ring: bool = False  # Use PF_RING for high-speed capture
    use_dpdk: bool = False  # Use DPDK (requires separate setup)
    batch_size: int = 64  # Packets per batch


class PacketCapture:
    """
    High-performance packet capture using Scapy's AsyncSniffer with async support.
    Supports BPF filters, promiscuous mode, and stats collection.
    """

    def __init__(self, config: PacketCaptureConfig, packet_handler: Optional[Callable] = None):
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is required for packet capture. Install with: pip install scapy")
        
        self.config = config
        self.packet_handler = packet_handler
        self.sniffer: Optional[scapy.AsyncSniffer] = None
        self.is_running = False
        self.packet_count = 0
        self.byte_count = 0
        self.start_time = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None

        # Rate limiting
        self.packet_timestamps = deque(maxlen=1000)
        self.dropped_packets = 0

        # Stats
        self.stats = {
            'packets_received': 0,
            'packets_dropped': 0,
            'bytes_received': 0,
            'packets_per_second': 0,
            'bits_per_second': 0,
            'errors': 0,
        }

        # Async queue for packet processing (set in start_async)
        self.packet_queue: Optional[asyncio.Queue] = None

        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        logger.info(f"Received signal {signum}, stopping capture...")
        self.stop()

    def _rate_limit_check(self) -> bool:
        """
        Check if we're exceeding the rate limit.
        Returns True if packet should be processed, False if dropped.
        """
        now = time.time()
        self.packet_timestamps.append(now)

        if len(self.packet_timestamps) < 2:
            return True

        window_start = now - 1.0
        packets_in_window = sum(1 for t in self.packet_timestamps if t >= window_start)
        current_rate = packets_in_window  # packets per second

        if current_rate > self.config.max_packets_per_second:
            self.dropped_packets += 1
            if self.dropped_packets % 1000 == 0:
                logger.warning(
                    f"Rate limit exceeded: {current_rate:.0f} pps, "
                    f"dropped {self.dropped_packets} packets"
                )
            return False

        return True

    def _process_packet(self, packet: Packet) -> Optional[Dict[str, Any]]:
        """
        Process a single packet and extract relevant information.
        Returns a dictionary of packet metadata or None if filtered out.
        """
        try:
            # Basic packet info
            packet_info = {
                'timestamp': time.time(),
                'timestamp_ns': time.time_ns(),
                'length': len(packet),
                'raw_packet': packet if self.config.capture_raw_packets else None,
            }

            # Ethernet layer
            if Ether in packet:
                packet_info['eth_src'] = packet[Ether].src
                packet_info['eth_dst'] = packet[Ether].dst

            # IP layer
            if IP in packet:
                ip_layer = packet[IP]
                packet_info['ip_src'] = ip_layer.src
                packet_info['ip_dst'] = ip_layer.dst
                packet_info['protocol'] = ip_layer.proto
                packet_info['ttl'] = ip_layer.ttl
                packet_info['ip_len'] = ip_layer.len
                packet_info['ip_id'] = ip_layer.id
                packet_info['tos'] = ip_layer.tos
            else:
                # Non-IP packet (ignore for flow building)
                return None

            # TCP layer
            if TCP in packet:
                tcp = packet[TCP]
                packet_info['sport'] = tcp.sport
                packet_info['dport'] = tcp.dport
                packet_info['tcp_flags'] = tcp.flags
                packet_info['tcp_seq'] = tcp.seq
                packet_info['tcp_ack'] = tcp.ack
                packet_info['tcp_window'] = tcp.window

                # HTTP header extraction (optional)
                if self.config.capture_http_headers and (tcp.dport == 80 or tcp.sport == 80):
                    try:
                        payload = bytes(tcp.payload)
                        if payload.startswith(b'GET') or payload.startswith(b'POST') or payload.startswith(b'HTTP'):
                            http_lines = payload.split(b'\r\n')
                            if http_lines:
                                request_line = http_lines[0].decode('utf-8', errors='ignore')
                                parts = request_line.split(' ')
                                if len(parts) >= 2:
                                    if parts[0] in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD']:
                                        packet_info['http_method'] = parts[0]
                                        packet_info['http_path'] = parts[1]
                    except Exception as e:
                        logger.debug(f"HTTP extraction failed: {e}")

            # UDP layer
            elif UDP in packet:
                udp = packet[UDP]
                packet_info['sport'] = udp.sport
                packet_info['dport'] = udp.dport
                packet_info['udp_len'] = udp.len

                # DNS query extraction (optional)
                if self.config.capture_dns_queries and (udp.dport == 53 or udp.sport == 53):
                    try:
                        from scapy.layers.dns import DNS
                        if DNS in packet:
                            dns = packet[DNS]
                            if dns.qr == 0:  # Query
                                if dns.qd:
                                    packet_info['dns_query'] = dns.qd.qname.decode('utf-8', errors='ignore')
                    except Exception as e:
                        logger.debug(f"DNS extraction failed: {e}")

            # ICMP layer
            elif ICMP in packet:
                icmp = packet[ICMP]
                packet_info['icmp_type'] = icmp.type
                packet_info['icmp_code'] = icmp.code

            return packet_info

        except Exception as e:
            logger.error(f"Error processing packet: {e}")
            self.stats['errors'] += 1
            return None

    def _packet_callback(self, packet: Packet):
        """Callback for each captured packet"""
        if not self.is_running:
            return

        # Rate limiting
        if not self._rate_limit_check():
            self.stats['packets_dropped'] += 1
            return

        # Process packet
        packet_info = self._process_packet(packet)
        if packet_info is None:
            return

        self.packet_count += 1
        self.byte_count += packet_info['length']

        # Use event loop if available for async processing
        if self._loop is not None and not self._loop.is_closed() and self.packet_queue is not None:
            self._loop.call_soon_threadsafe(self._enqueue_packet, packet_info)
        elif self.packet_handler:
            # Synchronous fallback
            self.packet_handler(packet_info)

    def _enqueue_packet(self, packet_info: Dict[str, Any]):
        """Put a packet onto the async queue (must be called from the event loop thread)."""
        if self.packet_queue is None:
            return
            
        try:
            self.packet_queue.put_nowait(packet_info)
        except asyncio.QueueFull:
            self.stats['packets_dropped'] += 1
            logger.warning("Packet queue full — dropping packet")

    async def start_async(self):
        """Start packet capture asynchronously"""
        self.is_running = True
        self.start_time = time.time()
        self.packet_queue = asyncio.Queue(maxsize=10000)
        self._loop = asyncio.get_event_loop()

        logger.info(f"Starting packet capture on interface {self.config.interface}")
        logger.info(f"Filter: {self.config.filter_bpf or 'none'}")
        logger.info(f"Promiscuous mode: {self.config.promiscuous}")

        try:
            self.sniffer = scapy.AsyncSniffer(
                iface=self.config.interface,
                filter=self.config.filter_bpf if self.config.filter_bpf else None,
                prn=self._packet_callback,
                store=False,
                promisc=self.config.promiscuous,
                count=0,  # Unlimited
                timeout=1,
            )
            self.sniffer.start()
        except Exception as e:
            logger.error(f"Failed to start packet capture: {e}")
            self.is_running = False
            raise

    def start_sync(self):
        """Start packet capture synchronously (blocking)."""
        self.is_running = True
        self.start_time = time.time()
        self._loop = None  # no event loop on sync path

        logger.info(f"Starting synchronous packet capture on {self.config.interface}")

        try:
            scapy.sniff(
                iface=self.config.interface,
                filter=self.config.filter_bpf if self.config.filter_bpf else None,
                prn=self._packet_callback,
                store=False,
                promisc=self.config.promiscuous,
                count=0,
                timeout=None,
            )
        except Exception as e:
            logger.error(f"Capture error: {e}")
        finally:
            self.is_running = False

    def stop(self):
        """Stop packet capture."""
        logger.info("Stopping packet capture...")
        self.is_running = False

        if self.sniffer is not None:
            try:
                self.sniffer.stop()
            except Exception as e:
                logger.warning(f"Error stopping sniffer: {e}")

        self._log_stats()

    def _log_stats(self):
        """Log capture statistics"""
        if not self.config.enable_stats:
            return

        duration = time.time() - self.start_time if self.start_time else 1
        pps = self.packet_count / duration if duration > 0 else 0
        bps = (self.byte_count * 8) / duration if duration > 0 else 0

        self.stats.update({
            'packets_received': self.packet_count,
            'bytes_received': self.byte_count,
            'packets_per_second': pps,
            'bits_per_second': bps,
        })

        logger.info("=" * 50)
        logger.info("Capture Statistics:")
        logger.info(f"  Duration: {duration:.2f} seconds")
        logger.info(f"  Packets: {self.packet_count:,}")
        logger.info(f"  Bytes: {self.byte_count:,}")
        logger.info(f"  PPS: {pps:.0f}")
        logger.info(f"  BPS: {bps:.0f} ({bps/1e6:.2f} Mbps)")
        logger.info(f"  Dropped: {self.stats['packets_dropped']:,}")
        logger.info(f"  Errors: {self.stats['errors']:,}")
        logger.info("=" * 50)

    async def get_packet(self, timeout: Optional[float] = None) -> Optional[Dict[str, Any]]:
        """Get next packet from the queue"""
        if self.packet_queue is None:
            return None
            
        try:
            return await asyncio.wait_for(self.packet_queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None

    async def run_pipeline(self, flow_builder):
        """Run the complete capture pipeline"""
        await self.start_async()

        try:
            while self.is_running:
                packet = await self.get_packet(timeout=1.0)
                if packet and flow_builder:
                    flow_builder.process_packet(packet)
        finally:
            self.stop()


# Convenience function for quick capture
async def capture_packets(
    interface: str = "eth0",
    duration: int = 10,
    filter_bpf: str = "",
) -> List[Dict[str, Any]]:
    """
    Capture packets for a specified duration and return them as a list.

    Args:
        interface: Network interface to capture from
        duration: Capture duration in seconds
        filter_bpf: BPF filter string

    Returns:
        List of packet dictionaries
    """
    config = PacketCaptureConfig(
        interface=interface,
        filter_bpf=filter_bpf,
    )

    capture = PacketCapture(config)
    packets: List[Dict[str, Any]] = []

    await capture.start_async()

    # Drain the queue for the requested duration
    deadline = asyncio.get_event_loop().time() + duration
    while asyncio.get_event_loop().time() < deadline:
        remaining = deadline - asyncio.get_event_loop().time()
        packet = await capture.get_packet(timeout=min(1.0, remaining))
        if packet:
            packets.append(packet)

    capture.stop()
    return packets