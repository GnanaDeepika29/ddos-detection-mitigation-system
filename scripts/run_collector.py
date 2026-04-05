#!/usr/bin/env python3
"""
Run script for the flow collector service.
"""

import os
import sys
import asyncio
import signal
import logging
import argparse
import random
import time
from pathlib import Path
from typing import Dict, Any

# Add parent directory to path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.collector.packet_capture import PacketCapture, PacketCaptureConfig
from src.collector.flow_builder import FlowBuilder
from src.monitoring.metrics_exporter import MetricsConfig, MetricsExporter
from src.streaming.producer import FlowProducer, ProducerConfig
from src.utils.logger import setup_logging

logger = logging.getLogger(__name__)


class CollectorService:
    """Main collector service"""
    
    def __init__(self, interface: str = "eth0", synthetic: bool = False):
        self.interface = interface
        self.synthetic = synthetic
        self.is_running = False
        self.snapshot_interval_seconds = float(
            os.environ.get("COLLECTOR_REALTIME_SNAPSHOT_INTERVAL_SECONDS", 0.25)
        )
        self._last_snapshot_publish: Dict[str, float] = {}
        
        # Initialize components
        capture_config = PacketCaptureConfig(
            interface=interface,
            promiscuous=True,
            filter_bpf=os.environ.get("CAPTURE_FILTER", ""),
        )
        self.capture = PacketCapture(capture_config)
        
        self.flow_builder = FlowBuilder(
            idle_timeout=int(os.environ.get("FLOW_IDLE_TIMEOUT", 30)),
            active_timeout=int(os.environ.get("FLOW_ACTIVE_TIMEOUT", 60)),
            max_flows=int(os.environ.get("MAX_FLOWS", 100000)),
        )
        
        producer_config = ProducerConfig(
            bootstrap_servers=os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"),
            topic_flows=os.environ.get("KAFKA_TOPIC_FLOWS", "network_flows"),
        )
        self.producer = FlowProducer(producer_config)
        self.metrics_exporter = MetricsExporter(MetricsConfig(
            enabled=os.environ.get("PROMETHEUS_ENABLED", "true").lower() == "true",
            port=int(os.environ.get("PROMETHEUS_PORT", os.environ.get("METRICS_PORT", 9091))),
        ))

    def _build_synthetic_flow(self) -> Dict[str, Any]:
        """Generate a synthetic flow for lab/demo environments."""
        now = time.time()
        attack_profile = os.environ.get("COLLECTOR_SYNTHETIC_PATTERN", "mixed").lower()
        is_attack = attack_profile in {"attack", "syn_flood"} or (
            attack_profile == "mixed" and random.random() < 0.25
        )
        src_octet = random.randint(1, 254)
        total_packets = random.randint(800, 2500) if is_attack else random.randint(10, 120)
        total_bytes = total_packets * random.randint(60, 800)
        return {
            "flow_id": f"synthetic_{int(now * 1000)}_{random.randint(1000, 9999)}",
            "ip_src": f"192.168.{random.randint(0, 10)}.{src_octet}",
            "ip_dst": os.environ.get("COLLECTOR_SYNTHETIC_TARGET_IP", "10.0.0.1"),
            "protocol": 6 if is_attack else random.choice([6, 17]),
            "sport": random.randint(1024, 65535),
            "dport": 80 if is_attack else random.choice([53, 80, 443, 8080]),
            "first_seen": now - random.uniform(0.1, 2.0),
            "last_seen": now,
            "duration": random.uniform(0.1, 2.0),
            "packets": total_packets,
            "bytes": total_bytes,
            "packets_reverse": 0 if is_attack else random.randint(0, 10),
            "bytes_reverse": 0 if is_attack else random.randint(0, 5000),
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "packets_per_sec": total_packets / max(0.1, random.uniform(0.1, 1.0)),
            "bytes_per_sec": total_bytes / max(0.1, random.uniform(0.1, 1.0)),
            "avg_packet_size": total_bytes / max(total_packets, 1),
            "tcp_syn_count": total_packets if is_attack else random.randint(0, 5),
            "tcp_syn_ack_count": 0 if is_attack else random.randint(1, 10),
            "tcp_rst_count": 0,
            "tcp_fin_count": 0 if is_attack else random.randint(0, 3),
            "tcp_window_avg": random.randint(1024, 65535),
            "udp_payload_avg": 0,
            "application_protocol": "HTTP" if is_attack else random.choice(["HTTP", "DNS", "HTTPS"]),
        }

    async def _run_synthetic(self):
        """Run a synthetic flow generator instead of packet capture."""
        interval = float(os.environ.get("COLLECTOR_SYNTHETIC_INTERVAL", 0.1))
        logger.info("Starting collector in synthetic mode")
        while self.is_running:
            flow = self._build_synthetic_flow()
            self.producer.send_flow(flow)
            self.metrics_exporter.set_packets_per_second(flow.get("packets_per_sec", 0))
            self.metrics_exporter.set_bytes_per_second(flow.get("bytes_per_sec", 0))
            self.metrics_exporter.set_flows_per_second(1.0 / max(interval, 0.001))
            await asyncio.sleep(max(0.001, interval))

    def _should_publish_snapshot(self, flow_id: str, now: float) -> bool:
        """Throttle active flow snapshots to keep Kafka traffic manageable."""
        last_sent = self._last_snapshot_publish.get(flow_id)
        if last_sent is None or (now - last_sent) >= self.snapshot_interval_seconds:
            self._last_snapshot_publish[flow_id] = now
            return True
        return False
        
    async def run(self):
        """Run the collector service"""
        logger.info("Starting collector service...")
        
        # Start Kafka producer
        self.producer.start()
        self.metrics_exporter.start_http_server()
        self.is_running = True

        if self.synthetic or os.environ.get("COLLECTOR_MODE", "").lower() == "synthetic":
            try:
                await self._run_synthetic()
            except asyncio.CancelledError:
                logger.info("Synthetic collector cancelled")
            finally:
                self.stop()
            return

        # Start packet capture
        await self.capture.start_async()
        
        try:
            while self.is_running:
                # Get packet from capture
                packet = await self.capture.get_packet(timeout=1.0)
                
                if packet:
                    # Process packet through flow builder
                    flow = self.flow_builder.process_packet(packet)
                    
                    # Send completed flow to Kafka
                    if flow:
                        flow_dict = flow.to_dict()
                        flow_dict["flow_state"] = "exported"
                        flow_dict["is_snapshot"] = False
                        self.producer.send_flow(flow_dict)
                        self.metrics_exporter.set_packets_per_second(flow_dict.get("packets_per_sec", 0))
                        self.metrics_exporter.set_bytes_per_second(flow_dict.get("bytes_per_sec", 0))
                        self.metrics_exporter.set_flows_per_second(1)
                    else:
                        active_flow = self.flow_builder.last_processed_flow
                        if active_flow:
                            snapshot = active_flow.to_dict()
                            if self._should_publish_snapshot(snapshot["flow_id"], time.time()):
                                snapshot["flow_state"] = "active"
                                snapshot["is_snapshot"] = True
                                self.producer.send_flow(snapshot)
                
                # Flush producer periodically
                if self.capture.packet_count % 1000 == 0:
                    self.producer.flush()
                    
                # Log stats
                if self.capture.packet_count % 10000 == 0 and self.capture.packet_count > 0:
                    logger.info(f"Captured {self.capture.packet_count} packets, "
                              f"{len(self.flow_builder.flows)} active flows")
                    
        except asyncio.CancelledError:
            logger.info("Collector service cancelled")
        finally:
            self.stop()
    
    def stop(self):
        """Stop the collector service"""
        self.is_running = False
        self.metrics_exporter.stop_http_server()
        if getattr(self.capture, "is_running", False):
            self.capture.stop()
        for flow in self.flow_builder.flush_all():
            flow_dict = flow.to_dict()
            flow_dict["flow_state"] = "exported"
            flow_dict["is_snapshot"] = False
            self.producer.send_flow(flow_dict)
        self.producer.flush()
        self.producer.stop()
        logger.info("Collector service stopped")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="DDoS Flow Collector")
    parser.add_argument("--interface", "-i", default=os.environ.get("COLLECTOR_INTERFACE", "eth0"),
                       help="Network interface to capture from")
    parser.add_argument("--synthetic", action="store_true",
                       help="Use synthetic traffic generation")
    parser.add_argument("--log-level", default=os.environ.get("LOG_LEVEL", "INFO"),
                       help="Log level")
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging()
    logging.getLogger().setLevel(getattr(logging, args.log_level.upper()))
    
    # Create and run service
    service = CollectorService(interface=args.interface, synthetic=args.synthetic)
    
    # Handle shutdown signals
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    for sig in [signal.SIGINT, signal.SIGTERM]:
        loop.add_signal_handler(sig, service.stop)
    
    try:
        loop.run_until_complete(service.run())
    except KeyboardInterrupt:
        logger.info("Received interrupt signal")
    finally:
        loop.close()


if __name__ == "__main__":
    main()
