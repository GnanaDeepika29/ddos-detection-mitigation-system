"""
Alert Manager Module

Manages alerts from the DDoS detection system and sends notifications
to multiple channels including Slack, PagerDuty, Email, and Webhooks.
"""

import asyncio
import json
import logging
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class AlertSeverity(Enum):
    """Alert severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertChannel(Enum):
    """Notification channels"""
    SLACK = "slack"
    PAGERDUTY = "pagerduty"
    EMAIL = "email"
    WEBHOOK = "webhook"
    TEAMS = "teams"
    OPSGENIE = "opsgenie"


@dataclass
class Alert:
    """Alert data structure"""
    id: str
    title: str
    description: str
    severity: AlertSeverity
    timestamp: float
    attack_type: Optional[str] = None
    confidence: float = 0.0
    source_ips: List[str] = field(default_factory=list)
    target_ips: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary"""
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity.value,
            'timestamp': self.timestamp,
            'attack_type': self.attack_type,
            'confidence': self.confidence,
            'source_ips': self.source_ips[:20],
            'target_ips': self.target_ips[:20],
            'details': self.details,
        }


@dataclass
class AlertConfig:
    """Configuration for alert manager"""
    enabled: bool = True

    # Deduplication settings
    deduplication_window_seconds: int = 60
    max_alerts_per_minute: int = 100

    # Severity filtering
    min_severity: AlertSeverity = AlertSeverity.LOW

    # Auto-resolution
    auto_resolve_seconds: int = 3600

    # Slack configuration
    slack_enabled: bool = False
    slack_webhook_url: str = ""

    # PagerDuty configuration
    pagerduty_enabled: bool = False
    pagerduty_integration_key: str = ""
    pagerduty_dashboard_url: str = ""

    # Email configuration
    email_enabled: bool = False
    email_smtp_host: str = ""
    email_smtp_port: int = 587
    email_smtp_user: str = ""
    email_smtp_password: str = ""
    email_from: str = ""
    email_to: List[str] = field(default_factory=list)

    # Webhook configuration
    webhook_enabled: bool = False
    webhook_url: str = ""
    webhook_headers: Dict[str, str] = field(default_factory=dict)

    # Teams configuration
    teams_enabled: bool = False
    teams_webhook_url: str = ""


class NotificationProvider:
    """Base class for notification providers"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.name = self.__class__.__name__

    async def send(self, alert: Alert) -> bool:
        """Send notification for an alert"""
        raise NotImplementedError


class SlackProvider(NotificationProvider):
    """Slack notification provider"""
    
    async def send(self, alert: Alert) -> bool:
        try:
            import aiohttp

            webhook_url = self.config.get('webhook_url')
            if not webhook_url:
                logger.error("Slack webhook URL not configured")
                return False

            colors = {
                AlertSeverity.CRITICAL: "#ff0000",
                AlertSeverity.HIGH: "#ff6600",
                AlertSeverity.MEDIUM: "#ffcc00",
                AlertSeverity.LOW: "#00cc00",
                AlertSeverity.INFO: "#0066cc",
            }

            message = {
                "attachments": [
                    {
                        "color": colors.get(alert.severity, "#cccccc"),
                        "title": f"[{alert.severity.value.upper()}] {alert.title}",
                        "text": alert.description,
                        "fields": [
                            {"title": "Attack Type", "value": alert.attack_type or "N/A", "short": True},
                            {"title": "Confidence", "value": f"{alert.confidence:.2%}", "short": True},
                            {"title": "Source IPs", "value": ", ".join(alert.source_ips[:5]) or "N/A", "short": False},
                            {"title": "Target IPs", "value": ", ".join(alert.target_ips[:5]) or "N/A", "short": False},
                            {"title": "PPS", "value": str(alert.details.get('pps', 'N/A')), "short": True},
                            {"title": "BPS", "value": str(alert.details.get('bps', 'N/A')), "short": True},
                        ],
                        "footer": "DDoS Protection System",
                        "ts": int(alert.timestamp),
                    }
                ]
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=message) as response:
                    return response.status == 200

        except ImportError:
            logger.error("aiohttp not installed")
            return False
        except Exception as e:
            logger.error(f"Failed to send Slack alert: {e}")
            return False


class PagerDutyProvider(NotificationProvider):
    """PagerDuty notification provider"""
    
    async def send(self, alert: Alert) -> bool:
        try:
            import aiohttp

            integration_key = self.config.get('integration_key')
            if not integration_key:
                logger.error("PagerDuty integration key not configured")
                return False

            severity_map = {
                AlertSeverity.CRITICAL: "critical",
                AlertSeverity.HIGH: "error",
                AlertSeverity.MEDIUM: "warning",
                AlertSeverity.LOW: "info",
                AlertSeverity.INFO: "info",
            }

            event = {
                "routing_key": integration_key,
                "event_action": "trigger",
                "payload": {
                    "summary": alert.title,
                    "severity": severity_map.get(alert.severity, "warning"),
                    "source": "ddos-detection-system",
                    "component": "detection-engine",
                    "group": alert.attack_type or "unknown",
                    "class": "ddos-attack",
                    "details": {
                        "description": alert.description,
                        "confidence": alert.confidence,
                        "source_ips": alert.source_ips[:10],
                        "target_ips": alert.target_ips[:10],
                        "attack_details": alert.details,
                    },
                },
                "links": [
                    {
                        "href": self.config.get('dashboard_url', ''),
                        "text": "View Dashboard",
                    }
                ],
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    "https://events.pagerduty.com/v2/enqueue", json=event
                ) as response:
                    return response.status == 202

        except ImportError:
            logger.error("aiohttp not installed")
            return False
        except Exception as e:
            logger.error(f"Failed to send PagerDuty alert: {e}")
            return False


class EmailProvider(NotificationProvider):
    """Email notification provider"""
    
    async def send(self, alert: Alert) -> bool:
        try:
            import smtplib
            from email.mime.multipart import MIMEMultipart
            from email.mime.text import MIMEText

            smtp_host = self.config.get('smtp_host')
            smtp_port = self.config.get('smtp_port', 587)
            smtp_user = self.config.get('smtp_user')
            smtp_password = self.config.get('smtp_password')
            from_email = self.config.get('from_email')
            to_emails = self.config.get('to_emails', [])

            if not all([smtp_host, from_email, to_emails]):
                logger.error("Email configuration incomplete")
                return False

            msg = MIMEMultipart()
            msg['From'] = from_email
            msg['To'] = ', '.join(to_emails)
            msg['Subject'] = f"[{alert.severity.value.upper()}] DDoS Alert: {alert.title}"

            body = f"""
DDoS Attack Alert
=================

Severity:    {alert.severity.value}
Attack Type: {alert.attack_type or 'Unknown'}
Confidence:  {alert.confidence:.2%}
Time:        {datetime.fromtimestamp(alert.timestamp).isoformat()}

Description: {alert.description}

Source IPs: {', '.join(alert.source_ips[:10])}
Target IPs: {', '.join(alert.target_ips[:10])}

Details:
{json.dumps(alert.details, indent=2)}
"""
            msg.attach(MIMEText(body, 'plain'))

            # Run in executor to avoid blocking
            loop = asyncio.get_event_loop()
            
            def _send():
                with smtplib.SMTP(smtp_host, smtp_port) as server:
                    if smtp_port == 587:
                        server.starttls()
                    if smtp_user and smtp_password:
                        server.login(smtp_user, smtp_password)
                    server.send_message(msg)

            await loop.run_in_executor(None, _send)

            logger.info(f"Email alert sent to {len(to_emails)} recipients")
            return True

        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
            return False


class WebhookProvider(NotificationProvider):
    """Webhook notification provider"""
    
    async def send(self, alert: Alert) -> bool:
        try:
            import aiohttp

            webhook_url = self.config.get('webhook_url')
            headers = self.config.get('headers', {'Content-Type': 'application/json'})

            if not webhook_url:
                logger.error("Webhook URL not configured")
                return False

            payload = {
                "alert": alert.to_dict(),
                "timestamp": datetime.utcnow().isoformat(),
                "system": "ddos-protection",
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=payload, headers=headers) as response:
                    return response.status in [200, 201, 202, 204]

        except ImportError:
            logger.error("aiohttp not installed")
            return False
        except Exception as e:
            logger.error(f"Failed to send webhook alert: {e}")
            return False


class TeamsProvider(NotificationProvider):
    """Microsoft Teams notification provider"""
    
    async def send(self, alert: Alert) -> bool:
        try:
            import aiohttp

            webhook_url = self.config.get('webhook_url')
            if not webhook_url:
                logger.error("Teams webhook URL not configured")
                return False

            colors = {
                AlertSeverity.CRITICAL: "FF0000",
                AlertSeverity.HIGH: "FF6600",
                AlertSeverity.MEDIUM: "FFCC00",
                AlertSeverity.LOW: "00CC00",
                AlertSeverity.INFO: "0066CC",
            }

            message = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": colors.get(alert.severity, "CCCCCC"),
                "summary": f"DDoS Alert: {alert.title}",
                "sections": [
                    {
                        "activityTitle": f"[{alert.severity.value.upper()}] {alert.title}",
                        "activitySubtitle": (
                            f"Detected at {datetime.fromtimestamp(alert.timestamp).isoformat()}"
                        ),
                        "facts": [
                            {"name": "Attack Type", "value": alert.attack_type or "N/A"},
                            {"name": "Confidence", "value": f"{alert.confidence:.2%}"},
                            {"name": "Source IPs", "value": ", ".join(alert.source_ips[:5]) or "N/A"},
                            {"name": "Target IPs", "value": ", ".join(alert.target_ips[:5]) or "N/A"},
                            {"name": "PPS", "value": str(alert.details.get('pps', 'N/A'))},
                            {"name": "BPS", "value": str(alert.details.get('bps', 'N/A'))},
                        ],
                        "text": alert.description,
                        "markdown": True,
                    }
                ],
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=message) as response:
                    return response.status == 200

        except Exception as e:
            logger.error(f"Failed to send Teams alert: {e}")
            return False


class AlertManager:
    """
    Central alert manager for DDoS detection system.
    Handles alert creation, deduplication, and notification routing.
    """

    def __init__(self, config: Optional[AlertConfig] = None):
        self.config = config or AlertConfig()

        self.active_alerts: Dict[str, Alert] = {}
        self.alert_history: deque = deque(maxlen=10000)
        self.recent_alerts: deque = deque(maxlen=1000)

        self.providers: List[NotificationProvider] = []
        self._init_providers()

        self.stats = {
            'alerts_created': 0,
            'alerts_resolved': 0,
            'alerts_deduplicated': 0,
            'notifications_sent': 0,
            'notifications_failed': 0,
        }

        self._running = False
        self._cleanup_thread = None

        logger.info("AlertManager initialized")

    def _init_providers(self):
        """Initialize notification providers based on configuration"""
        if self.config.slack_enabled and self.config.slack_webhook_url:
            self.providers.append(SlackProvider({'webhook_url': self.config.slack_webhook_url}))

        if self.config.pagerduty_enabled and self.config.pagerduty_integration_key:
            self.providers.append(PagerDutyProvider({
                'integration_key': self.config.pagerduty_integration_key,
                'dashboard_url': self.config.pagerduty_dashboard_url,
            }))

        if self.config.email_enabled and self.config.email_to:
            self.providers.append(EmailProvider({
                'smtp_host': self.config.email_smtp_host,
                'smtp_port': self.config.email_smtp_port,
                'smtp_user': self.config.email_smtp_user,
                'smtp_password': self.config.email_smtp_password,
                'from_email': self.config.email_from,
                'to_emails': self.config.email_to,
            }))

        if self.config.webhook_enabled and self.config.webhook_url:
            self.providers.append(WebhookProvider({
                'webhook_url': self.config.webhook_url,
                'headers': self.config.webhook_headers,
            }))

        if self.config.teams_enabled and self.config.teams_webhook_url:
            self.providers.append(TeamsProvider({'webhook_url': self.config.teams_webhook_url}))

        logger.info(f"Initialized {len(self.providers)} notification providers")

    def _generate_alert_id(self) -> str:
        """Generate unique alert ID"""
        return uuid.uuid4().hex[:16]

    def _is_duplicate(self, alert: Alert) -> bool:
        """Check if alert is a duplicate of a recent alert"""
        for recent in self.recent_alerts:
            if (recent.attack_type == alert.attack_type
                    and recent.severity == alert.severity
                    and abs(recent.timestamp - alert.timestamp)
                    < self.config.deduplication_window_seconds):
                return True
        return False

    def _schedule_notifications(self, alert: Alert):
        """Schedule notification sending"""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(self._send_notifications(alert))
                return
        except RuntimeError:
            pass

        # No running loop in this thread — run in a dedicated thread
        threading.Thread(
            target=lambda: asyncio.run(self._send_notifications(alert)),
            daemon=True,
            name=f"alert-notifier-{alert.id}",
        ).start()

    def create_alert(
        self,
        title: str,
        description: str,
        severity: AlertSeverity,
        attack_type: Optional[str] = None,
        confidence: float = 0.0,
        source_ips: Optional[List[str]] = None,
        target_ips: Optional[List[str]] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> Optional[Alert]:
        """
        Create a new alert and dispatch notifications.

        Returns:
            Alert object if created, None if filtered or duplicate
        """
        # Filter by severity
        severity_order = [
            AlertSeverity.INFO, AlertSeverity.LOW,
            AlertSeverity.MEDIUM, AlertSeverity.HIGH, AlertSeverity.CRITICAL,
        ]

        if severity_order.index(severity) < severity_order.index(self.config.min_severity):
            logger.debug(f"Alert filtered: severity {severity.value} below minimum")
            return None

        # Create alert
        alert = Alert(
            id=self._generate_alert_id(),
            title=title,
            description=description,
            severity=severity,
            timestamp=time.time(),
            attack_type=attack_type,
            confidence=confidence,
            source_ips=source_ips or [],
            target_ips=target_ips or [],
            details=details or {},
        )

        # Deduplication check
        if self._is_duplicate(alert):
            self.stats['alerts_deduplicated'] += 1
            logger.debug(f"Duplicate alert suppressed: {title}")
            return None

        # Store alert
        self.active_alerts[alert.id] = alert
        self.recent_alerts.append(alert)
        self.alert_history.append(alert)

        self.stats['alerts_created'] += 1
        logger.info(
            f"Alert created: [{severity.value.upper()}] {title} "
            f"(confidence={confidence:.2f})"
        )

        # Send notifications
        self._schedule_notifications(alert)

        return alert

    async def _send_notifications(self, alert: Alert):
        """Send notifications to all providers"""
        tasks = [self._send_to_provider(p, alert) for p in self.providers]
        if not tasks:
            return

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Notification failed: {result}")
                self.stats['notifications_failed'] += 1
            elif result:
                self.stats['notifications_sent'] += 1

    async def _send_to_provider(self, provider: NotificationProvider, alert: Alert) -> bool:
        """Send alert to a specific provider"""
        try:
            return await provider.send(alert)
        except Exception as e:
            logger.error(f"Provider {provider.name} failed: {e}")
            return False

    def resolve_alert(self, alert_id: str) -> bool:
        """Resolve an active alert"""
        if alert_id in self.active_alerts:
            alert = self.active_alerts.pop(alert_id)
            self.stats['alerts_resolved'] += 1
            logger.info(f"Alert resolved: {alert.title}")
            return True
        return False

    def resolve_all_alerts(self):
        """Resolve all active alerts"""
        count = len(self.active_alerts)
        self.active_alerts.clear()
        self.stats['alerts_resolved'] += count
        logger.info(f"Resolved all {count} active alerts")

    def get_active_alerts(self) -> List[Dict[str, Any]]:
        """Get list of active alerts"""
        return [alert.to_dict() for alert in self.active_alerts.values()]

    def get_alert_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get alert history"""
        return [alert.to_dict() for alert in list(self.alert_history)[-limit:]]

    def get_stats(self) -> Dict[str, Any]:
        """Get alert manager statistics"""
        return {
            **self.stats,
            'active_alerts': len(self.active_alerts),
            'alert_history_size': len(self.alert_history),
            'providers_configured': len(self.providers),
            'deduplication_window': self.config.deduplication_window_seconds,
            'min_severity': self.config.min_severity.value,
            'enabled': self.config.enabled,
        }

    def start(self):
        """Start the alert manager (cleanup thread)"""
        if self._running:
            return
        self._running = True
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop, daemon=True
        )
        self._cleanup_thread.start()
        logger.info("AlertManager started")

    def _cleanup_loop(self):
        """Background cleanup thread for auto-resolving old alerts"""
        while self._running:
            time.sleep(60)

            if self.config.auto_resolve_seconds > 0:
                now = time.time()
                expired = [
                    aid for aid, a in list(self.active_alerts.items())
                    if now - a.timestamp > self.config.auto_resolve_seconds
                ]
                for alert_id in expired:
                    self.resolve_alert(alert_id)

    def stop(self):
        """Stop the alert manager"""
        self._running = False
        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=5)
        logger.info("AlertManager stopped")

    def create_attack_alert(self, detection_result: Dict[str, Any]) -> Optional[Alert]:
        """Convenience method to create an alert from a detection result"""
        severity_map = {
            'critical': AlertSeverity.CRITICAL,
            'high': AlertSeverity.HIGH,
            'medium': AlertSeverity.MEDIUM,
            'low': AlertSeverity.LOW,
        }

        severity = severity_map.get(
            detection_result.get('severity', 'medium'), AlertSeverity.MEDIUM
        )

        return self.create_alert(
            title=f"DDoS Attack Detected: {detection_result.get('attack_type', 'Unknown')}",
            description=(
                f"A potential DDoS attack has been detected. "
                f"Confidence: {detection_result.get('confidence', 0):.2%}"
            ),
            severity=severity,
            attack_type=detection_result.get('attack_type'),
            confidence=detection_result.get('confidence', 0),
            source_ips=detection_result.get('source_ips', []),
            target_ips=detection_result.get('target_ips', []),
            details=detection_result,
        )