"""
Live Packet Capture Module

Captures raw packets from network interfaces using Scapy or libpcap,
performs basic filtering, and forwards packets to FlowBuilder.
"""

import asyncio
import logging
import signal
import threading
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
    snaplen: int = 1518        # Maximum bytes per packet
    timeout: int = 1           # Packet capture timeout (seconds)
    filter_bpf: str = ""       # BPF filter (e.g., "tcp or udp")
    buffer_size_mb: int = 64   # Capture buffer size
    max_packets_per_second: int = 100000  # Throttle if exceeded
    enable_stats: bool = True
    capture_raw_packets: bool = False
    capture_http_headers: bool = False
    capture_dns_queries: bool = False

    # Performance settings
    use_pf_ring: bool = False   # Use PF_RING for high-speed capture
    use_dpdk: bool = False      # Use DPDK (requires separate setup)
    batch_size: int = 64        # Packets per batch


class PacketCapture:
    """
    High-performance packet capture using Scapy's AsyncSniffer with async support.
    Supports BPF filters, promiscuous mode, and stats collection.
    """

    def __init__(self, config: PacketCaptureConfig, packet_handler: Optional[Callable] = None):
        if not SCAPY_AVAILABLE:
            raise ImportError(
                "Scapy is required for packet capture. Install with: pip install scapy"
            )

        self.config = config
        self.packet_handler = packet_handler
        self.sniffer: Optional[scapy.AsyncSniffer] = None
        self.is_running = False
        self.packet_count = 0
        self.byte_count = 0
        self.start_time: Optional[float] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None

        # Rate limiting
        self.packet_timestamps: deque = deque(maxlen=1000)
        self.dropped_packets = 0

        # Stats
        self.stats: Dict[str, Any] = {
            'packets_received': 0,
            'packets_dropped': 0,
            'bytes_received': 0,
            'packets_per_second': 0,
            'bits_per_second': 0,
            'errors': 0,
        }

        # Async queue for packet processing (set in start_async)
        self.packet_queue: Optional[asyncio.Queue] = None

        # FIX BUG-3: signal.signal() can only be called from the main thread.
        # Registering handlers unconditionally raises ValueError when this class
        # is instantiated from a worker thread (e.g. inside an executor).
        if threading.current_thread() is threading.main_thread():
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
        else:
            logger.debug(
                "PacketCapture instantiated from a non-main thread; "
                "skipping signal handler registration."
            )

    def _signal_handler(self, signum: int, frame: Any) -> None:
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

        if packets_in_window > self.config.max_packets_per_second:
            self.dropped_packets += 1
            if self.dropped_packets % 1000 == 0:
                logger.warning(
                    f"Rate limit exceeded: {packets_in_window} pps, "
                    f"dropped {self.dropped_packets} packets total"
                )
            return False

        return True

    def _process_packet(self, packet: "Packet") -> Optional[Dict[str, Any]]:
        """
        Process a single packet and extract relevant information.
        Returns a dictionary of packet metadata or None if filtered out.
        """
        try:
            packet_info: Dict[str, Any] = {
                'timestamp': time.time(),
                'timestamp_ns': time.time_ns(),
                'length': len(packet),
                'raw_packet': packet if self.config.capture_raw_packets else None,
            }

            # Ethernet layer
            if Ether in packet:
                packet_info['eth_src'] = packet[Ether].src
                packet_info['eth_dst'] = packet[Ether].dst

            # IP layer — non-IP packets are skipped for flow building
            if IP not in packet:
                return None

            ip_layer = packet[IP]
            packet_info.update({
                'ip_src': ip_layer.src,
                'ip_dst': ip_layer.dst,
                'protocol': ip_layer.proto,
                'ttl': ip_layer.ttl,
                'ip_len': ip_layer.len,
                'ip_id': ip_layer.id,
                'tos': ip_layer.tos,
            })

            # TCP layer
            if TCP in packet:
                tcp = packet[TCP]
                packet_info.update({
                    'sport': tcp.sport,
                    'dport': tcp.dport,
                    'tcp_flags': int(tcp.flags),
                    'tcp_seq': tcp.seq,
                    'tcp_ack': tcp.ack,
                    'tcp_window': tcp.window,
                })

                # Optional HTTP header extraction (port 80 only)
                if self.config.capture_http_headers and tcp.dport in (80, 8080) or (
                    self.config.capture_http_headers and tcp.sport in (80, 8080)
                ):
                    try:
                        payload = bytes(tcp.payload)
                        if payload[:4] in (b'GET ', b'POST', b'HTTP', b'PUT ', b'DELE', b'HEAD'):
                            lines = payload.split(b'\r\n')
                            if lines:
                                first = lines[0].decode('utf-8', errors='ignore').split(' ')
                                if len(first) >= 2 and first[0] in (
                                    'GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'PATCH'
                                ):
                                    packet_info['http_method'] = first[0]
                                    packet_info['http_path'] = first[1]
                    except Exception as exc:
                        logger.debug(f"HTTP extraction failed: {exc}")

            # UDP layer
            elif UDP in packet:
                udp = packet[UDP]
                packet_info.update({
                    'sport': udp.sport,
                    'dport': udp.dport,
                    'udp_len': udp.len,
                })

                # Optional DNS query extraction
                if self.config.capture_dns_queries and (
                    udp.dport == 53 or udp.sport == 53
                ):
                    try:
                        from scapy.layers.dns import DNS
                        if DNS in packet:
                            dns = packet[DNS]
                            if dns.qr == 0 and dns.qd:  # Query
                                packet_info['dns_query'] = dns.qd.qname.decode(
                                    'utf-8', errors='ignore'
                                )
                    except Exception as exc:
                        logger.debug(f"DNS extraction failed: {exc}")

            # ICMP layer
            elif ICMP in packet:
                icmp = packet[ICMP]
                packet_info.update({
                    'icmp_type': icmp.type,
                    'icmp_code': icmp.code,
                    # ICMP has no ports; default to 0 so flow builder can key on them
                    'sport': 0,
                    'dport': 0,
                })

            return packet_info

        except Exception as exc:
            logger.error(f"Error processing packet: {exc}")
            self.stats['errors'] += 1
            return None

    def _packet_callback(self, packet: "Packet") -> None:
        """Callback invoked for each captured packet (runs in sniffer thread)."""
        if not self.is_running:
            return

        if not self._rate_limit_check():
            self.stats['packets_dropped'] += 1
            return

        packet_info = self._process_packet(packet)
        if packet_info is None:
            return

        self.packet_count += 1
        self.byte_count += packet_info['length']

        # FIX BUG-5: Log when a packet has nowhere to go instead of silently
        # dropping it.  The loop+queue path is the preferred async route.
        if self._loop is not None and not self._loop.is_closed() and self.packet_queue is not None:
            # call_soon_threadsafe is correct here — sniffer runs in its own
            # thread and we need to schedule work on the asyncio event loop.
            self._loop.call_soon_threadsafe(self._enqueue_packet, packet_info)
        elif self.packet_handler:
            self.packet_handler(packet_info)
        else:
            logger.debug("Packet received but no queue or handler configured — dropped.")

    def _enqueue_packet(self, packet_info: Dict[str, Any]) -> None:
        """Put a packet onto the async queue (must be called from the event loop thread)."""
        if self.packet_queue is None:
            return
        try:
            self.packet_queue.put_nowait(packet_info)
        except asyncio.QueueFull:
            self.stats['packets_dropped'] += 1
            logger.warning("Packet queue full — dropping packet")

    async def start_async(self) -> None:
        """Start packet capture asynchronously."""
        self.is_running = True
        self.start_time = time.time()
        self.packet_queue = asyncio.Queue(maxsize=10000)

        # FIX BUG-1 / BUG-4: asyncio.get_event_loop() is deprecated in
        # Python ≥3.10 and raises RuntimeError in ≥3.12 when called from a
        # coroutine.  Use get_running_loop() instead — it is always available
        # inside an async context.
        self._loop = asyncio.get_running_loop()

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
                count=0,    # Unlimited
                timeout=1,
            )
            self.sniffer.start()
        except Exception as exc:
            logger.error(f"Failed to start packet capture: {exc}")
            self.is_running = False
            raise

    def start_sync(self) -> None:
        """Start packet capture synchronously (blocking)."""
        self.is_running = True
        self.start_time = time.time()
        self._loop = None   # No event loop on the sync path

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
        except Exception as exc:
            logger.error(f"Capture error: {exc}")
        finally:
            self.is_running = False

    def stop(self) -> None:
        """Stop packet capture."""
        logger.info("Stopping packet capture...")
        self.is_running = False

        if self.sniffer is not None:
            try:
                self.sniffer.stop()
            except Exception as exc:
                logger.warning(f"Error stopping sniffer: {exc}")

        self._log_stats()

    def _log_stats(self) -> None:
        """Log capture statistics."""
        if not self.config.enable_stats:
            return

        duration = (time.time() - self.start_time) if self.start_time else 1.0
        duration = max(duration, 1e-6)  # Guard against division by zero
        pps = self.packet_count / duration
        bps = (self.byte_count * 8) / duration

        self.stats.update({
            'packets_received': self.packet_count,
            'bytes_received': self.byte_count,
            'packets_per_second': pps,
            'bits_per_second': bps,
        })

        logger.info("=" * 50)
        logger.info("Capture Statistics:")
        logger.info(f"  Duration:   {duration:.2f}s")
        logger.info(f"  Packets:    {self.packet_count:,}")
        logger.info(f"  Bytes:      {self.byte_count:,}")
        logger.info(f"  PPS:        {pps:.0f}")
        logger.info(f"  BPS:        {bps:.0f}  ({bps / 1e6:.2f} Mbps)")
        logger.info(f"  Dropped:    {self.stats['packets_dropped']:,}")
        logger.info(f"  Errors:     {self.stats['errors']:,}")
        logger.info("=" * 50)

    async def get_packet(self, timeout: Optional[float] = None) -> Optional[Dict[str, Any]]:
        """Get the next packet from the async queue."""
        if self.packet_queue is None:
            return None
        try:
            return await asyncio.wait_for(self.packet_queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None

    async def run_pipeline(self, flow_builder: Any) -> None:
        """Run the complete capture-to-flow-builder pipeline."""
        await self.start_async()

        try:
            while self.is_running:
                packet = await self.get_packet(timeout=1.0)
                if packet and flow_builder:
                    flow_builder.process_packet(packet)
        finally:
            self.stop()


# ---------------------------------------------------------------------------
# Convenience helper
# ---------------------------------------------------------------------------

async def capture_packets(
    interface: str = "eth0",
    duration: int = 10,
    filter_bpf: str = "",
) -> List[Dict[str, Any]]:
    """
    Capture packets for a specified duration and return them as a list.

    Args:
        interface:   Network interface to capture from.
        duration:    Capture duration in seconds.
        filter_bpf:  BPF filter string.

    Returns:
        List of packet-info dictionaries.
    """
    config = PacketCaptureConfig(
        interface=interface,
        filter_bpf=filter_bpf,
    )

    capture = PacketCapture(config)
    packets: List[Dict[str, Any]] = []

    await capture.start_async()

    # FIX BUG-7: asyncio.get_event_loop().time() is deprecated in ≥3.10.
    # Use asyncio.get_running_loop() which is always valid inside a coroutine.
    loop = asyncio.get_running_loop()
    deadline = loop.time() + duration

    while loop.time() < deadline:
        remaining = deadline - loop.time()
        packet = await capture.get_packet(timeout=min(1.0, remaining))
        if packet:
            packets.append(packet)

    capture.stop()
    return packets