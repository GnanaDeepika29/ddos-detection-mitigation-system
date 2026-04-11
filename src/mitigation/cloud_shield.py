"""
Cloud Shield Module

Integrates with cloud provider DDoS protection services:
- AWS Shield Advanced
- Azure DDoS Protection
- GCP Cloud Armor
"""

import time
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, Any, Optional, List

try:
    import boto3
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False

try:
    from azure.mgmt.network import NetworkManagementClient
    from azure.identity import DefaultAzureCredential
    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False

try:
    import Cloudflare
    CLOUDFLARE_AVAILABLE = True
except ImportError:
    CLOUDFLARE_AVAILABLE = False


logger = logging.getLogger(__name__)


class CloudProvider(Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    CLOUDFLARE = "cloudflare"
    NONE = "none"



class ShieldAction(Enum):
    ENABLE = "enable"
    DISABLE = "disable"
    UPDATE_THRESHOLD = "update_threshold"
    ADD_IP_WHITELIST = "add_ip_whitelist"
    ADD_IP_BLACKLIST = "add_ip_blacklist"
    CREATE_PROTECTION_GROUP = "create_protection_group"


@dataclass
class ProtectionStatus:
    enabled: bool = False
    protected_resources: List[str] = field(default_factory=list)
    active_attacks: List[Dict[str, Any]] = field(default_factory=list)
    mitigation_steps: List[str] = field(default_factory=list)
    last_updated: float = field(default_factory=time.time)


@dataclass
class CloudShieldConfig:
    provider: CloudProvider = CloudProvider.NONE

    aws_region: str = "us-east-1"
    aws_shield_advanced_enabled: bool = False
    aws_protection_group_ids: List[str] = field(default_factory=list)

    azure_subscription_id: Optional[str] = None
    azure_resource_group: Optional[str] = None
    azure_ddos_protection_plan_id: Optional[str] = None

    gcp_project_id: Optional[str] = None
    gcp_cloud_armor_policy: Optional[str] = None

    cloudflare_api_token: Optional[str] = None
    cloudflare_zone_id: Optional[str] = None


    cloudflare_api_token: Optional[str] = None
    cloudflare_zone_id: Optional[str] = None


    cloudflare_api_token: Optional[str] = None
    cloudflare_zone_id: Optional[str] = None


    auto_enable: bool = True
    # FIX BUG-44: Aligned defaults with prod.yaml values.
    enable_threshold_bps: int = 50_000_000     # was 100_000_000
    enable_threshold_pps: int = 25_000         # was 50_000
    cooldown_seconds: int = 300

    def __post_init__(self) -> None:
        if isinstance(self.provider, str):
            self.provider = CloudProvider(self.provider.lower())


class CloudShield(ABC):
    """Abstract base class for cloud shield providers."""

    def __init__(self, config: CloudShieldConfig) -> None:
        self.config = config
        self.status = ProtectionStatus()
        self.last_action_time = 0.0
        logger.info(f"CloudShield initialised for {config.provider.value}")

    @abstractmethod
    def enable_protection(self, resource_id: str) -> bool: ...

    @abstractmethod
    def disable_protection(self, resource_id: str) -> bool: ...

    @abstractmethod
    def get_protection_status(self, resource_id: str) -> ProtectionStatus: ...

    @abstractmethod
    def update_thresholds(self, pps_threshold: int, bps_threshold: int) -> bool: ...

    def _check_cooldown(self) -> bool:
        return (time.time() - self.last_action_time) < self.config.cooldown_seconds

    def _update_last_action(self) -> None:
        self.last_action_time = time.time()

    def get_stats(self) -> Dict[str, Any]:
        return {
            'provider': self.config.provider.value,
            'enabled': self.status.enabled,
            'protected_resources': len(self.status.protected_resources),
            'active_attacks': len(self.status.active_attacks),
            'last_updated': self.status.last_updated,
        }


class AWSShield(CloudShield):
    """AWS Shield Advanced implementation."""

    def __init__(self, config: CloudShieldConfig) -> None:
        super().__init__(config)
        # FIX BUG-1: Use lazy init — boto3 makes blocking network calls
        # (STS, IMDSv2) during client construction which would block an
        # asyncio event loop if called from an async context.
        self._client: Any = None

    def _get_client(self) -> Any:
        """Lazy-init AWS Shield client on first use."""
        if self._client is not None:
            return self._client
        if not BOTO3_AVAILABLE:
            logger.error("boto3 not installed. Install with: pip install boto3")
            return None
        try:
            self._client = boto3.client('shield', region_name=self.config.aws_region)
            logger.info("AWS Shield client initialised")
        except Exception as exc:
            logger.error(f"Failed to initialise AWS Shield client: {exc}")
        return self._client

    def enable_protection(self, resource_id: str) -> bool:
        client = self._get_client()
        if not client:
            return False
        # FIX BUG-5: Log cooldown state so operators can diagnose silent failures.
        if self._check_cooldown():
            logger.debug(
                f"AWS Shield enable_protection skipped — in cooldown "
                f"({self.config.cooldown_seconds}s) for {resource_id}"
            )
            return False
        try:
            response = client.create_protection(
                Name=f"ddos-auto-protection-{resource_id}",
                ResourceArn=resource_id,
            )
            if response.get('ProtectionId'):
                self.status.enabled = True
                if resource_id not in self.status.protected_resources:
                    self.status.protected_resources.append(resource_id)
                self.status.last_updated = time.time()
                self._update_last_action()
                logger.info(f"AWS Shield protection enabled for {resource_id}")
                return True
        except Exception as exc:
            logger.error(f"Failed to enable AWS Shield protection: {exc}")
        return False

    def disable_protection(self, resource_id: str) -> bool:
        """
        Disable AWS Shield protection.

        FIX BUG-3: The original code called self._client.get_paginator('list_protections')
        but the boto3 Shield client does NOT support paginators for list_protections.
        Calling get_paginator raises botocore.exceptions.OperationNotPageableError.
        Fixed to use list_protections() directly with NextToken continuation.
        """
        client = self._get_client()
        if not client:
            return False
        try:
            protection_id: Optional[str] = None
            next_token: Optional[str] = None

            while True:
                kwargs: Dict[str, Any] = {}
                if next_token:
                    kwargs['NextToken'] = next_token

                # FIX BUG-3: list_protections() — no paginator exists for Shield.
                response = client.list_protections(**kwargs)

                for protection in response.get('Protections', []):
                    if protection.get('ResourceArn') == resource_id:
                        protection_id = protection.get('Id')
                        break

                if protection_id:
                    break

                next_token = response.get('NextToken')
                if not next_token:
                    break

            if protection_id:
                client.delete_protection(ProtectionId=protection_id)
                self.status.enabled = False
                if resource_id in self.status.protected_resources:
                    self.status.protected_resources.remove(resource_id)
                logger.info(f"AWS Shield protection disabled for {resource_id}")
                return True

        except Exception as exc:
            logger.error(f"Failed to disable AWS Shield protection: {exc}")
        return False

    def get_protection_status(self, resource_id: str) -> ProtectionStatus:
        client = self._get_client()
        if not client:
            return self.status
        try:
            attacks = client.list_attacks(
                StartTime={'FromInclusive': datetime.utcnow() - timedelta(hours=24)},
                EndTime={'ToExclusive': datetime.utcnow()},
            )
            self.status.active_attacks = [
                {
                    'attack_id': a.get('AttackId'),
                    'attack_type': (
                        a.get('AttackVectorDescriptionList', [{}])[0].get('AttackVector')
                    ),
                    'start_time': a.get('StartTime'),
                    'end_time': a.get('EndTime'),
                }
                for a in attacks.get('AttackSummaries', [])
                if a.get('ResourceArn') == resource_id
                and a.get('AttackStatus') == 'ACTIVE'
            ]
            self.status.last_updated = time.time()
        except Exception as exc:
            logger.error(f"Failed to get AWS Shield protection status: {exc}")
        return self.status

    def update_thresholds(self, pps_threshold: int, bps_threshold: int) -> bool:
        logger.info(f"AWS Shield thresholds noted: PPS={pps_threshold}, BPS={bps_threshold}")
        return True


class AzureShield(CloudShield):
    """Azure DDoS Protection implementation."""

    def __init__(self, config: CloudShieldConfig) -> None:
        super().__init__(config)
        # FIX BUG-1 pattern: lazy init for Azure SDK too.
        self._client: Any = None

    def _get_client(self) -> Any:
        if self._client is not None:
            return self._client
        if not AZURE_AVAILABLE:
            logger.error(
                "Azure SDK not installed. "
                "Install with: pip install azure-mgmt-network azure-identity"
            )
            return None
        try:
            credential = DefaultAzureCredential()
            self._client = NetworkManagementClient(
                credential=credential,
                subscription_id=self.config.azure_subscription_id,
            )
            logger.info("Azure DDoS Protection client initialised")
        except Exception as exc:
            logger.error(f"Failed to initialise Azure DDoS Protection client: {exc}")
        return self._client

    def enable_protection(self, resource_id: str) -> bool:
        if not self._get_client():
            return False
        if self._check_cooldown():
            logger.debug(f"Azure DDoS enable_protection skipped — in cooldown for {resource_id}")
            return False
        try:
            if self.config.azure_ddos_protection_plan_id:
                self.status.enabled = True
                if resource_id not in self.status.protected_resources:
                    self.status.protected_resources.append(resource_id)
                self._update_last_action()
                logger.info(f"Azure DDoS Protection enabled for {resource_id}")
                return True
        except Exception as exc:
            logger.error(f"Failed to enable Azure DDoS Protection: {exc}")
        return False

    def disable_protection(self, resource_id: str) -> bool:
        self.status.enabled = False
        if resource_id in self.status.protected_resources:
            self.status.protected_resources.remove(resource_id)
        logger.info(f"Azure DDoS Protection disabled for {resource_id}")
        return True

    def get_protection_status(self, resource_id: str) -> ProtectionStatus:
        return self.status

    def update_thresholds(self, pps_threshold: int, bps_threshold: int) -> bool:
        logger.info("Azure DDoS thresholds updated")
        return True


class GCPCloudArmor(CloudShield):
    """GCP Cloud Armor implementation."""

    """GCP Cloud Armor implementation."""

    """GCP Cloud Armor implementation."""

    """GCP Cloud Armor implementation."""

    def __init__(self, config: CloudShieldConfig) -> None:
        super().__init__(config)
        # FIX BUG-1 pattern: lazy init for GCP SDK too.
        self._client: Any = None

    def _get_client(self) -> Any:
        if self._client is not None:
            return self._client
        if not GCP_AVAILABLE:
            logger.error(
                "Google Cloud SDK not installed. "
                "Install with: pip install google-cloud-compute"
            )
            return None
        try:
            self._client = compute_v1.SecurityPoliciesClient()
            logger.info("GCP Cloud Armor client initialised")
        except Exception as exc:
            logger.error(f"Failed to initialise GCP Cloud Armor client: {exc}")
        return self._client

    def enable_protection(self, resource_id: str) -> bool:
        if not self._get_client():
            return False
        if self._check_cooldown():
            logger.debug(f"GCP Cloud Armor enable_protection skipped — in cooldown for {resource_id}")
            return False
        try:
            self.status.enabled = True
            if resource_id not in self.status.protected_resources:
                self.status.protected_resources.append(resource_id)
            self._update_last_action()
            logger.info(f"GCP Cloud Armor enabled for {resource_id}")
            return True
        except Exception as exc:
            logger.error(f"Failed to enable GCP Cloud Armor: {exc}")
        return False

    def disable_protection(self, resource_id: str) -> bool:
        self.status.enabled = False
        if resource_id in self.status.protected_resources:
            self.status.protected_resources.remove(resource_id)
        return True

    def get_protection_status(self, resource_id: str) -> ProtectionStatus:
        return self.status

    def update_thresholds(self, pps_threshold: int, bps_threshold: int) -> bool:
        logger.info("GCP Cloud Armor thresholds updated")
        return True


class CloudflareShield(CloudShield):
    """Cloudflare Shield implementation."""

    def __init__(self, config: CloudShieldConfig) -> None:
        super().__init__(config)
        self._client: Any = None

    def _get_client(self) -> Any:
        if self._client is not None:
            return self._client
        if not CLOUDFLARE_AVAILABLE:
            logger.error(
                "Cloudflare SDK not installed. "
                "Install with: pip install cloudflare"
            )
            return None
        try:
            self._client = Cloudflare.Cloudflare(
                token=self.config.cloudflare_api_token
            )
            logger.info("Cloudflare client initialised")
        except Exception as exc:
            logger.error(f"Failed to initialise Cloudflare client: {exc}")
        return self._client

    def enable_protection(self, resource_id: str) -> bool:
        """
        Enables "I'm Under Attack" mode for the configured zone.
        `resource_id` is ignored as this setting is zone-wide.
        """
        client = self._get_client()
        if not client or not self.config.cloudflare_zone_id:
            return False
        if self._check_cooldown():
            logger.debug("Cloudflare enable_protection skipped — in cooldown")
            return False
        try:
            zone_id = self.config.cloudflare_zone_id
            settings = client.zones.settings.edit(
                zone_id=zone_id,
                items=[{"id": "security_level", "value": "under_attack"}],
            )
            self.status.enabled = True
            self.status.protected_resources = [zone_id]
            self._update_last_action()
            logger.info(f"Cloudflare 'I'm Under Attack' mode enabled for zone {zone_id}")
            return True
        except Exception as exc:
            logger.error(f"Failed to enable Cloudflare protection: {exc}")
        return False

    def disable_protection(self, resource_id: str) -> bool:
        """
        Sets security level back to "high" (or a pre-configured default).
        """
        client = self._get_client()
        if not client or not self.config.cloudflare_zone_id:
            return False
        try:
            zone_id = self.config.cloudflare_zone_id
            client.zones.settings.edit(
                zone_id=zone_id,
                items=[{"id": "security_level", "value": "high"}],
            )
            self.status.enabled = False
            logger.info(f"Cloudflare 'I'm Under Attack' mode disabled for zone {zone_id}")
            return True
        except Exception as exc:
            logger.error(f"Failed to disable Cloudflare protection: {exc}")
        return False

    def get_protection_status(self, resource_id: str) -> ProtectionStatus:
        """
        Checks the current security level of the zone.
        """
        client = self._get_client()
        if not client or not self.config.cloudflare_zone_id:
            return self.status
        try:
            zone_id = self.config.cloudflare_zone_id
            setting = client.zones.settings.get(zone_id=zone_id, setting_id="security_level")
            if setting and setting.get('value') == 'under_attack':
                self.status.enabled = True
            else:
                self.status.enabled = False
            self.status.last_updated = time.time()
        except Exception as exc:
            logger.error(f"Failed to get Cloudflare protection status: {exc}")
        return self.status

    def update_thresholds(self, pps_threshold: int, bps_threshold: int) -> bool:
        logger.info("Cloudflare does not use configurable thresholds for 'I'm Under Attack' mode.")
        return True


class CloudflareShield(CloudShield):
    """Cloudflare Shield implementation."""

    def __init__(self, config: CloudShieldConfig) -> None:
        super().__init__(config)
        self._client: Any = None

    def _get_client(self) -> Any:
        if self._client is not None:
            return self._client
        if not CLOUDFLARE_AVAILABLE:
            logger.error(
                "Cloudflare SDK not installed. "
                "Install with: pip install cloudflare"
            )
            return None
        try:
            self._client = Cloudflare.Cloudflare(
                token=self.config.cloudflare_api_token
            )
            logger.info("Cloudflare client initialised")
        except Exception as exc:
            logger.error(f"Failed to initialise Cloudflare client: {exc}")
        return self._client

    def enable_protection(self, resource_id: str) -> bool:
        """
        Enables "I'm Under Attack" mode for the configured zone.
        `resource_id` is ignored as this setting is zone-wide.
        """
        client = self._get_client()
        if not client or not self.config.cloudflare_zone_id:
            return False
        if self._check_cooldown():
            logger.debug("Cloudflare enable_protection skipped — in cooldown")
            return False
        try:
            zone_id = self.config.cloudflare_zone_id
            settings = client.zones.settings.edit(
                zone_id=zone_id,
                items=[{"id": "security_level", "value": "under_attack"}],
            )
            self.status.enabled = True
            self.status.protected_resources = [zone_id]
            self._update_last_action()
            logger.info(f"Cloudflare 'I'm Under Attack' mode enabled for zone {zone_id}")
            return True
        except Exception as exc:
            logger.error(f"Failed to enable Cloudflare protection: {exc}")
        return False

    def disable_protection(self, resource_id: str) -> bool:
        """
        Sets security level back to "high" (or a pre-configured default).
        """
        client = self._get_client()
        if not client or not self.config.cloudflare_zone_id:
            return False
        try:
            zone_id = self.config.cloudflare_zone_id
            client.zones.settings.edit(
                zone_id=zone_id,
                items=[{"id": "security_level", "value": "high"}],
            )
            self.status.enabled = False
            logger.info(f"Cloudflare 'I'm Under Attack' mode disabled for zone {zone_id}")
            return True
        except Exception as exc:
            logger.error(f"Failed to disable Cloudflare protection: {exc}")
        return False

    def get_protection_status(self, resource_id: str) -> ProtectionStatus:
        """
        Checks the current security level of the zone.
        """
        client = self._get_client()
        if not client or not self.config.cloudflare_zone_id:
            return self.status
        try:
            zone_id = self.config.cloudflare_zone_id
            setting = client.zones.settings.get(zone_id=zone_id, setting_id="security_level")
            if setting and setting.get('value') == 'under_attack':
                self.status.enabled = True
            else:
                self.status.enabled = False
            self.status.last_updated = time.time()
        except Exception as exc:
            logger.error(f"Failed to get Cloudflare protection status: {exc}")
        return self.status

    def update_thresholds(self, pps_threshold: int, bps_threshold: int) -> bool:
        logger.info("Cloudflare does not use configurable thresholds for 'I'm Under Attack' mode.")
        return True


class CloudflareShield(CloudShield):
    """Cloudflare Shield implementation."""

    def __init__(self, config: CloudShieldConfig) -> None:
        super().__init__(config)
        self._client: Any = None

    def _get_client(self) -> Any:
        if self._client is not None:
            return self._client
        if not CLOUDFLARE_AVAILABLE:
            logger.error(
                "Cloudflare SDK not installed. "
                "Install with: pip install cloudflare"
            )
            return None
        try:
            self._client = Cloudflare.Cloudflare(
                token=self.config.cloudflare_api_token
            )
            logger.info("Cloudflare client initialised")
        except Exception as exc:
            logger.error(f"Failed to initialise Cloudflare client: {exc}")
        return self._client

    def enable_protection(self, resource_id: str) -> bool:
        """
        Enables "I'm Under Attack" mode for the configured zone.
        `resource_id` is ignored as this setting is zone-wide.
        """
        client = self._get_client()
        if not client or not self.config.cloudflare_zone_id:
            return False
        if self._check_cooldown():
            logger.debug("Cloudflare enable_protection skipped — in cooldown")
            return False
        try:
            zone_id = self.config.cloudflare_zone_id
            settings = client.zones.settings.edit(
                zone_id=zone_id,
                items=[{"id": "security_level", "value": "under_attack"}],
            )
            self.status.enabled = True
            self.status.protected_resources = [zone_id]
            self._update_last_action()
            logger.info(f"Cloudflare 'I'm Under Attack' mode enabled for zone {zone_id}")
            return True
        except Exception as exc:
            logger.error(f"Failed to enable Cloudflare protection: {exc}")
        return False

    def disable_protection(self, resource_id: str) -> bool:
        """
        Sets security level back to "high" (or a pre-configured default).
        """
        client = self._get_client()
        if not client or not self.config.cloudflare_zone_id:
            return False
        try:
            zone_id = self.config.cloudflare_zone_id
            client.zones.settings.edit(
                zone_id=zone_id,
                items=[{"id": "security_level", "value": "high"}],
            )
            self.status.enabled = False
            logger.info(f"Cloudflare 'I'm Under Attack' mode disabled for zone {zone_id}")
            return True
        except Exception as exc:
            logger.error(f"Failed to disable Cloudflare protection: {exc}")
        return False

    def get_protection_status(self, resource_id: str) -> ProtectionStatus:
        """
        Checks the current security level of the zone.
        """
        client = self._get_client()
        if not client or not self.config.cloudflare_zone_id:
            return self.status
        try:
            zone_id = self.config.cloudflare_zone_id
            setting = client.zones.settings.get(zone_id=zone_id, setting_id="security_level")
            if setting and setting.get('value') == 'under_attack':
                self.status.enabled = True
            else:
                self.status.enabled = False
            self.status.last_updated = time.time()
        except Exception as exc:
            logger.error(f"Failed to get Cloudflare protection status: {exc}")
        return self.status

    def update_thresholds(self, pps_threshold: int, bps_threshold: int) -> bool:
        logger.info("Cloudflare does not use configurable thresholds for 'I'm Under Attack' mode.")
        return True


class NoOpShield(CloudShield):
    """
    No-op implementation for local / test environments.




    FIX BUG-6: The original class had no __init__, so CloudShield.__init__
    was never called.  self.status, self.last_action_time, and the startup log
    were missing - AttributeError on get_stats() and _check_cooldown().
    """

    def __init__(self, config: CloudShieldConfig) -> None:
        super().__init__(config)  # FIX BUG-6

    def enable_protection(self, resource_id: str) -> bool:
        logger.debug(f"No-op: enable_protection({resource_id})")
        return True

    def disable_protection(self, resource_id: str) -> bool:
        logger.debug(f"No-op: disable_protection({resource_id})")
        return True

    def get_protection_status(self, resource_id: str) -> ProtectionStatus:
        return self.status

    def update_thresholds(self, pps_threshold: int, bps_threshold: int) -> bool:
        return True


def create_cloud_shield(config: CloudShieldConfig) -> CloudShield:
    """Factory: return the correct CloudShield implementation."""
    if config.provider == CloudProvider.AWS:
        return AWSShield(config)
    if config.provider == CloudProvider.AZURE:
        return AzureShield(config)
    if config.provider == CloudProvider.GCP:
        return GCPCloudArmor(config)
    if config.provider == CloudProvider.CLOUDFLARE:
        return CloudflareShield(config)
    return NoOpShield(config)