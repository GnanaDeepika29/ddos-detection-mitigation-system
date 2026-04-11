#!/usr/bin/env python3
"""
Run script for the mitigation service.
"""

import os
import sys
import asyncio
import signal
import logging
import argparse
from pathlib import Path

# Add parent directory to path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.streaming.consumer import FlowConsumer, ConsumerConfig
from src.mitigation.rule_injector import RuleInjector, RuleInjectorConfig
from src.mitigation.rate_limiter import DistributedRateLimiter, RateLimiterConfig
from src.mitigation.cloud_shield import CloudShield, CloudShieldConfig, CloudProvider, create_cloud_shield
from src.monitoring.metrics_exporter import MetricsExporter, MetricsConfig
from src.utils.logger import setup_logging

logger = logging.getLogger(__name__)


class MitigationService:
    """Main mitigation service"""
    
    def __init__(self):
        # Initialize components
        consumer_config = ConsumerConfig(
            bootstrap_servers=os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"),
            group_id=os.environ.get("KAFKA_CONSUMER_GROUP", "ddos-mitigation-group"),
            topics_alerts=[os.environ.get("KAFKA_TOPIC_ALERTS", "ddos_alerts")],
        )
        self.consumer = FlowConsumer(consumer_config)
        
        self.rule_injector = RuleInjector(RuleInjectorConfig(
            require_sudo=False,  # Set to True in production
            default_ttl_seconds=int(os.environ.get("BLACKLIST_DURATION_SECONDS", 3600)),
        ))
        
        self.rate_limiter = DistributedRateLimiter(
            RateLimiterConfig(
                default_packet_rate=int(os.environ.get("RATE_LIMIT_PPS", 1000)),
                enable_auto_rules=os.environ.get("AUTO_MITIGATE", "false").lower() == "true",
            ),
            redis_host=os.environ.get("REDIS_HOST", "localhost"),
            redis_port=int(os.environ.get("REDIS_PORT", 6379)),
        )
        
        cloud_config = CloudShieldConfig(
            provider=CloudProvider(os.environ.get("CLOUD_PROVIDER", "none").lower()),
            auto_enable=os.environ.get("AUTO_MITIGATE", "false").lower() == "true",
        )
        self.cloud_shield = create_cloud_shield(cloud_config)
        
        # Metrics exporter
        metrics_config = MetricsConfig(
            enabled=os.environ.get("PROMETHEUS_ENABLED", "true").lower() == "true",
            port=int(os.environ.get("PROMETHEUS_PORT", os.environ.get("METRICS_PORT", 9091))),
        )
        self.metrics_exporter = MetricsExporter(metrics_config)
        
        # Track active mitigations
        self.active_mitigations = {}
        
    async def run(self):
        """Run the mitigation service"""
        logger.info("Starting mitigation service...")
        
        # Start consumer
        self.consumer.start()
        self.metrics_exporter.start_http_server()
        
        # Register callbacks
        def on_alert(alert):
            self.handle_alert(alert)
        
        self.consumer.register_alert_callback(on_alert)
        
        # Run consumer loop
        try:
            await self.consumer.consume_async()
        except asyncio.CancelledError:
            logger.info("Mitigation service cancelled")
        finally:
            self.stop()
    
    def handle_alert(self, alert: dict):
        """Handle a detection alert"""
        attack_type = alert.get('attack_type', 'unknown')
        severity = alert.get('severity', 'medium')
        affected_ips = alert.get('affected_ips', [])
        
        logger.info(f"Handling alert: {attack_type} (severity={severity})")
        
        dry_run = os.environ.get("MITIGATION_DRY_RUN", "true").lower() == "true"
        
        if dry_run:
            logger.info(f"DRY RUN: Would mitigate {attack_type} affecting {affected_ips}")
            return
        
        # Apply mitigation based on severity
        if severity in ['critical', 'high']:
            for ip in affected_ips[:5]:  # Limit to first 5 IPs
                # Block IP
                rule_id = self.rule_injector.block_ip(
                    ip,
                    duration_seconds=int(os.environ.get("BLACKLIST_DURATION_SECONDS", 3600)),
                    reason=f"DDoS mitigation: {attack_type}"
                )
                
                # Rate limit
                rate_limit_id = self.rate_limiter.rate_limit_ip(
                    ip,
                    rate_pps=int(os.environ.get("RATE_LIMIT_PPS", 500)),
                )
                
                self.active_mitigations[ip] = {
                    'rule_id': rule_id,
                    'rate_limit_id': rate_limit_id,
                    'attack_type': attack_type,
                    'timestamp': alert.get('timestamp'),
                }
                
                logger.info(f"Applied mitigation to {ip}: block={rule_id}, rate_limit={rate_limit_id}")
                
                # Update metrics
                self.metrics_exporter.record_mitigation_action('block_ip', True)
                self.metrics_exporter.record_mitigation_action('rate_limit', True)
                self.metrics_exporter.set_blocked_ips(len(self.active_mitigations))
                self.metrics_exporter.set_active_rules(len(self.active_mitigations), 'all')
        
        elif severity == 'medium':
            for ip in affected_ips[:3]:
                # Only rate limit for medium severity
                rate_limit_id = self.rate_limiter.rate_limit_ip(
                    ip,
                    rate_pps=int(os.environ.get("RATE_LIMIT_PPS", 1000)),
                )
                logger.info(f"Applied rate limiting to {ip}: {rate_limit_id}")
                self.metrics_exporter.record_mitigation_action('rate_limit', True)
                self.metrics_exporter.set_active_rules(len(self.active_mitigations), 'all')
        
        # Cloud shield for critical attacks
        if severity == 'critical' and self.cloud_shield:
            for ip in affected_ips[:1]:
                self.cloud_shield.enable_protection(ip)
                logger.info(f"Enabled cloud shield for {ip}")
                self.metrics_exporter.record_mitigation_action('cloud_shield', True)
    
    def stop(self):
        """Stop the mitigation service"""
        self.metrics_exporter.stop_http_server()
        self.consumer.stop()
        logger.info("Mitigation service stopped")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="DDoS Mitigation Service")
    parser.add_argument("--log-level", default=os.environ.get("LOG_LEVEL", "INFO"),
                       help="Log level")
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging()
    logging.getLogger().setLevel(getattr(logging, args.log_level.upper()))
    
    # Create and run service
    service = MitigationService()
    
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