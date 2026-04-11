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
import time
from pathlib import Path
from typing import Any, Dict

# Add parent directory to path for relative imports
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.streaming.consumer import DetectionConsumer, ConsumerConfig
from src.streaming.window_aggregator import WindowAggregator
from src.detection.threshold_detector import ThresholdDetector, ThresholdConfig
from src.detection.ml_detector import MLDetector, MLDetectorConfig
from src.detection.ensemble import EnsembleDetector, EnsembleConfig, VotingStrategy
from src.monitoring.alert_manager import AlertManager, AlertConfig, AlertSeverity
from src.monitoring.metrics_exporter import MetricsExporter, MetricsConfig
from src.streaming.producer import FlowProducer, ProducerConfig
from src.utils.paths import resolve_project_path
from src.utils.logger import setup_logging

logger = logging.getLogger(__name__)


class DetectorService:
    """Main detector service - Production ready"""
    
    def __init__(self):
        # Initialize components with memory-friendly defaults
        consumer_config = ConsumerConfig(
            bootstrap_servers=os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"),
            group_id=os.environ.get("KAFKA_CONSUMER_GROUP", "ddos-detection-group"),
            topics_flows=[os.environ.get("KAFKA_TOPIC_FLOWS", "network_flows")],
        )
        self.consumer = DetectionConsumer(consumer_config)
        
        self.window_aggregator = WindowAggregator(
            window_sizes=[5, 60],
            history_size=50,
            enable_rolling_stats=True,
        )
        
        self.threshold_detector = ThresholdDetector(ThresholdConfig(
            packets_per_second_threshold=int(os.environ.get("DETECTION_THRESHOLD_PPS", "50000")),
            bytes_per_second_threshold=int(os.environ.get("DETECTION_THRESHOLD_BPS", "100000000")),
            entropy_src_ip_threshold=float(os.environ.get("ENTROPY_THRESHOLD", "0.7")),
        ))
        
        # ML detector (required for prod ensemble)
        default_model = resolve_project_path("models/isolation_forest.pkl")  # Use existing model
        ml_config = MLDetectorConfig(
            model_path=os.environ.get("ML_MODEL_PATH", str(default_model)),
            anomaly_threshold=float(os.environ.get("ML_ANOMALY_THRESHOLD", "0.5")),
        )
        self.ml_detector = MLDetector(ml_config)
        
        ensemble_config = EnsembleConfig(
            voting_strategy=VotingStrategy.WEIGHTED,
            threshold_weight=0.35,
            ml_weight=0.45,
            entropy_weight=0.20,
            min_confidence=0.7,
            min_agreeing_detectors=2,  # Prod min
        )
        self.ensemble_detector = EnsembleDetector(
            config=ensemble_config,
            threshold_detector=self.threshold_detector,
            ml_detector=self.ml_detector,
        )
        
        # Metrics (Prometheus standard)
        metrics_config = MetricsConfig(
            enabled=True,
            port=int(os.environ.get("METRICS_PORT", 9091)),
        )
        self.metrics_exporter = MetricsExporter(metrics_config)
        
        # Alert producer & manager
        self.alert_producer = FlowProducer(ProducerConfig(
            bootstrap_servers=os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"),
            topic_alerts=os.environ.get("KAFKA_TOPIC_ALERTS", "ddos_alerts_prod"),
            enable_idempotence=True,  # Prod durability
        ))

        self.alert_manager = AlertManager(AlertConfig(
            enabled=True,
            min_severity=AlertSeverity.MEDIUM,
            deduplication_window_seconds=60,
            max_alerts_per_minute=100,
            alert_history_maxlen=5000,
        ))
        
    async def run(self):
        logger.info("Starting production DDoS detector service...")
        self.consumer.start()
        self.alert_producer.start()
        self.metrics_exporter.start_http_server()
        self.alert_manager.start()
        
        def on_flow(flow):
            aggregated = self.window_aggregator.add_flow(flow)
            if aggregated:
                detection = self.ensemble_detector.detect_from_dict(aggregated)
                if detection and detection.is_attack:
                    logger.warning(f"*** DDoS ATTACK *** {detection.attack_type} (conf={detection.confidence:.1%})")
                    
                    # Prod metrics
                    self.metrics_exporter.record_attack(detection.attack_type)
                    
                    # Prod alerting
                    alert_payload = self._build_alert_payload(detection, aggregated)
                    self.alert_producer.send_alert(alert_payload)
                    self.alert_manager.create_attack_alert(detection.to_dict())
        
        self.consumer.register_flow_callback(on_flow)
        
        try:
            await self.consumer.consume_async()
        except asyncio.CancelledError:
            logger.info("Service cancelled gracefully")
        finally:
            self.stop()
    
    def stop(self):
        """Graceful shutdown - prod critical"""
        logger.info("Shutting down detector service...")
        self.alert_manager.stop()
        self.metrics_exporter.stop_http_server()
        self.alert_producer.stop()
        self.consumer.stop()
        logger.info("Detector service stopped")

    def _build_alert_payload(self, detection: Any, aggregated: Dict[str, Any]) -> Dict[str, Any]:
        """Standardized prod alert payload."""
        return {
            "timestamp": time.time(),
            "attack_type": detection.attack_type,
            "severity": str(detection.severity),
            "confidence": float(detection.confidence),
            "metrics": aggregated.get("metrics", {}),
            "details": getattr(detection, "details", {}),
        }


def main():
    parser = argparse.ArgumentParser(description="Production DDoS Detector")
    parser.add_argument("--log-level", default=os.environ.get("LOG_LEVEL", "INFO"))
    parser.add_argument("--config", help="Config file")
    
    args = parser.parse_args()
    
    # Prod logging
    setup_logging()
    logging.getLogger().setLevel(getattr(logging, args.log_level.upper()))
    
    service = DetectorService()
    
    # Production signal handling - Windows/Linux/Mac compatible
    loop = asyncio.get_event_loop_policy().new_event_loop()
    asyncio.set_event_loop(loop)
    
    # Windows-compatible shutdown (no add_signal_handler)
    def shutdown(sig=None, frame=None):
        logger.info(f"Shutdown signal: {sig}")
        loop.call_soon_threadsafe(loop.stop)
    
    # Register signals (works on Windows for SIGINT/TERM emulation)
    for s in (signal.SIGINT, signal.SIGTERM):
        signal.signal(s, shutdown)
    
    try:
        loop.run_until_complete(service.run())
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt")
    finally:
        service.stop()
        loop.close()


if __name__ == "__main__":
    main()

