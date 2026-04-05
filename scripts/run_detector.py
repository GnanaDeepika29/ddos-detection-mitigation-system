#!/usr/bin/env python3
"""
Run script for the DDoS detector service.
"""

import os
import sys
import asyncio
import signal
import logging
import argparse
from pathlib import Path
from typing import Any, Dict

# Add parent directory to path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.streaming.consumer import DetectionConsumer, ConsumerConfig
from src.streaming.window_aggregator import WindowAggregator
from src.detection.threshold_detector import ThresholdDetector, ThresholdConfig
from src.detection.ml_detector import MLDetector, MLDetectorConfig
from src.detection.ensemble import EnsembleDetector, EnsembleConfig
from src.monitoring.metrics_exporter import MetricsExporter, MetricsConfig
from src.streaming.producer import FlowProducer, ProducerConfig
from src.utils.logger import setup_logging

logger = logging.getLogger(__name__)


class DetectorService:
    """Main detector service"""
    
    def __init__(self):
        # Initialize components
        consumer_config = ConsumerConfig(
            bootstrap_servers=os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"),
            group_id=os.environ.get("KAFKA_CONSUMER_GROUP", "ddos-detection-group"),
            topics_flows=[os.environ.get("KAFKA_TOPIC_FLOWS", "network_flows")],
        )
        self.consumer = DetectionConsumer(consumer_config)
        
        self.window_aggregator = WindowAggregator(
            window_sizes=[1, 5, 10, 60],
            history_size=100,
            enable_rolling_stats=True,
        )
        
        self.threshold_detector = ThresholdDetector(ThresholdConfig(
            packets_per_second_threshold=int(os.environ.get("DETECTION_THRESHOLD_PPS", 10000)),
            bytes_per_second_threshold=int(os.environ.get("DETECTION_THRESHOLD_BPS", 100000000)),
            entropy_src_ip_threshold=float(os.environ.get("ENTROPY_THRESHOLD", 0.7)),
        ))
        
        # ML detector (optional)
        ml_config = MLDetectorConfig(
            model_path=os.environ.get(
                "ML_MODEL_PATH_ISOLATION_FOREST",
                os.environ.get("MODEL_PATH", "models/isolation_forest.pkl"),
            ),
            anomaly_threshold=float(os.environ.get("ML_CONFIDENCE_THRESHOLD", 0.7)),
        )
        self.ml_detector = MLDetector(ml_config)
        
        self.ensemble_detector = EnsembleDetector(
            config=EnsembleConfig(),
            threshold_detector=self.threshold_detector,
            ml_detector=self.ml_detector,
        )
        
        # Metrics exporter
        metrics_config = MetricsConfig(
            enabled=os.environ.get("PROMETHEUS_ENABLED", "true").lower() == "true",
            port=int(os.environ.get("PROMETHEUS_PORT", os.environ.get("METRICS_PORT", 9091))),
        )
        self.metrics_exporter = MetricsExporter(metrics_config)
        self.alert_producer = FlowProducer(ProducerConfig(
            bootstrap_servers=os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"),
            topic_alerts=os.environ.get("KAFKA_TOPIC_ALERTS", "ddos_alerts"),
        ))
        
    async def run(self):
        """Run the detector service"""
        logger.info("Starting detector service...")
        
        # Start consumer
        self.consumer.start()
        self.alert_producer.start()
        self.metrics_exporter.start_http_server()
        
        # Register callbacks
        def on_flow(flow):
            # Process flow through window aggregator
            aggregated = self.window_aggregator.add_flow(flow)
            
            if aggregated:
                # Run detection on aggregated stats
                detection = self.ensemble_detector.detect_from_dict(aggregated)
                
                if detection and detection.is_attack:
                    logger.info(f"Attack detected: {detection.attack_type} "
                              f"(confidence={detection.confidence:.2f})")
                    
                    # Update metrics
                    self.metrics_exporter.record_attack(detection.attack_type)
                    self.metrics_exporter.record_detection(detection.attack_type, detection.severity)
                    self.metrics_exporter.record_alert(detection.severity, detection.attack_type)
                    self.metrics_exporter.set_detection_confidence(
                        detection.attack_type, detection.confidence
                    )
                    self.metrics_exporter.set_packets_per_second(
                        aggregated.get("metrics", {}).get("packets_per_second", 0)
                    )
                    self.metrics_exporter.set_bytes_per_second(
                        aggregated.get("metrics", {}).get("bytes_per_second", 0)
                    )
                    self.metrics_exporter.set_flows_per_second(
                        aggregated.get("metrics", {}).get("flows_count", 0) / max(
                            aggregated.get("window_size_seconds", 1), 1
                        )
                    )
                    self.metrics_exporter.set_entropy_src_ip(
                        aggregated.get("metrics", {}).get("entropy_src_ip", 0)
                    )
                    self.metrics_exporter.set_entropy_dst_ip(
                        aggregated.get("metrics", {}).get("entropy_dst_ip", 0)
                    )
                    self.metrics_exporter.update_top_src_ips(
                        dict(aggregated.get("metrics", {}).get("top_src_ips", []))
                    )
                    self.metrics_exporter.update_top_dst_ips(
                        dict(aggregated.get("metrics", {}).get("top_dst_ips", []))
                    )
                    self.metrics_exporter.set_attack_intensity(
                        detection.attack_type,
                        aggregated.get("metrics", {}).get("packets_per_second", 0),
                    )
                    self.alert_producer.send_alert(self._build_alert_payload(detection, aggregated))

        self.consumer.register_flow_callback(on_flow)
        
        # Run consumer loop
        try:
            await self.consumer.consume_async()
        except asyncio.CancelledError:
            logger.info("Detector service cancelled")
        finally:
            self.stop()
    
    def stop(self):
        """Stop the detector service"""
        self.metrics_exporter.stop_http_server()
        self.alert_producer.flush()
        self.alert_producer.stop()
        self.consumer.stop()
        logger.info("Detector service stopped")

    def _build_alert_payload(self, detection: Any, aggregated: Dict[str, Any]) -> Dict[str, Any]:
        """Build a Kafka-friendly alert payload from a detection result."""
        metrics = aggregated.get("metrics", {})
        details = getattr(detection, "details", {})
        return {
            "attack_type": detection.attack_type,
            "severity": detection.severity,
            "confidence": detection.confidence,
            "timestamp": getattr(detection, "timestamp", None),
            "affected_ips": getattr(detection, "affected_ips", []),
            "consensus_method": getattr(detection, "consensus_method", "ensemble"),
            "details": {
                **details,
                "packets_per_second": metrics.get("packets_per_second", 0),
                "bytes_per_second": metrics.get("bytes_per_second", 0),
                "window_size_seconds": aggregated.get("window_size_seconds"),
            },
        }


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="DDoS Detector Service")
    parser.add_argument("--log-level", default=os.environ.get("LOG_LEVEL", "INFO"),
                       help="Log level")
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging()
    logging.getLogger().setLevel(getattr(logging, args.log_level.upper()))
    
    # Create and run service
    service = DetectorService()
    
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
