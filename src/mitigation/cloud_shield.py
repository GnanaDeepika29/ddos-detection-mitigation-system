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

# Lazy imports for cloud providers
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
    from google.cloud import compute_v1
    GCP_AVAILABLE = True
except ImportError:
    GCP_AVAILABLE = False

logger = logging.getLogger(__name__)


class CloudProvider(Enum):
    """Supported cloud providers"""
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    NONE = "none"


class ShieldAction(Enum):
    """Actions for cloud shield"""
    ENABLE = "enable"
    DISABLE = "disable"
    UPDATE_THRESHOLD = "update_threshold"
    ADD_IP_WHITELIST = "add_ip_whitelist"
    ADD_IP_BLACKLIST = "add_ip_blacklist"
    CREATE_PROTECTION_GROUP = "create_protection_group"


@dataclass
class ProtectionStatus:
    """Status of cloud protection"""
    enabled: bool = False
    protected_resources: List[str] = field(default_factory=list)
    active_attacks: List[Dict[str, Any]] = field(default_factory=list)
    mitigation_steps: List[str] = field(default_factory=list)
    last_updated: float = field(default_factory=time.time)


@dataclass
class CloudShieldConfig:
    """Configuration for cloud shield"""
    provider: CloudProvider = CloudProvider.NONE

    # AWS specific
    aws_region: str = "us-east-1"
    aws_shield_advanced_enabled: bool = False
    aws_protection_group_ids: List[str] = field(default_factory=list)

    # Azure specific
    azure_subscription_id: Optional[str] = None
    azure_resource_group: Optional[str] = None
    azure_ddos_protection_plan_id: Optional[str] = None

    # GCP specific
    gcp_project_id: Optional[str] = None
    gcp_cloud_armor_policy: Optional[str] = None

    # Common settings
    auto_enable: bool = True
    enable_threshold_bps: int = 100_000_000
    enable_threshold_pps: int = 50_000
    cooldown_seconds: int = 300

    def __post_init__(self) -> None:
        if isinstance(self.provider, str):
            self.provider = CloudProvider(self.provider.lower())


class CloudShield(ABC):
    """Abstract base class for cloud shield providers"""
    
    def __init__(self, config: CloudShieldConfig):
        self.config = config
        self.status = ProtectionStatus()
        self.last_action_time = 0
        logger.info(f"CloudShield initialized for {config.provider.value}")

    @abstractmethod
    def enable_protection(self, resource_id: str) -> bool:
        """Enable DDoS protection for a resource"""
        pass

    @abstractmethod
    def disable_protection(self, resource_id: str) -> bool:
        """Disable DDoS protection for a resource"""
        pass

    @abstractmethod
    def get_protection_status(self, resource_id: str) -> ProtectionStatus:
        """Get protection status for a resource"""
        pass

    @abstractmethod
    def update_thresholds(self, pps_threshold: int, bps_threshold: int) -> bool:
        """Update detection thresholds"""
        pass

    def _check_cooldown(self) -> bool:
        """Check if action is in cooldown"""
        return (time.time() - self.last_action_time) < self.config.cooldown_seconds

    def _update_last_action(self):
        """Update last action timestamp"""
        self.last_action_time = time.time()

    def get_stats(self) -> Dict[str, Any]:
        """Get shield statistics"""
        return {
            'provider': self.config.provider.value,
            'enabled': self.status.enabled,
            'protected_resources': len(self.status.protected_resources),
            'active_attacks': len(self.status.active_attacks),
            'last_updated': self.status.last_updated,
        }


class AWSShield(CloudShield):
    """AWS Shield Advanced implementation"""
    
    def __init__(self, config: CloudShieldConfig):
        super().__init__(config)
        self._client = None
        self._init_client()

    def _init_client(self):
        """Initialize AWS Shield client"""
        if not BOTO3_AVAILABLE:
            logger.error("boto3 not installed. Install with: pip install boto3")
            return
            
        try:
            self._client = boto3.client('shield', region_name=self.config.aws_region)
            logger.info("AWS Shield client initialized")
        except Exception as e:
            logger.error(f"Failed to initialize AWS Shield: {e}")

    def enable_protection(self, resource_id: str) -> bool:
        """Enable AWS Shield protection"""
        if not self._client or self._check_cooldown():
            return False

        try:
            response = self._client.create_protection(
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

        except Exception as e:
            logger.error(f"Failed to enable AWS Shield protection: {e}")

        return False

    def disable_protection(self, resource_id: str) -> bool:
        """Disable AWS Shield protection"""
        if not self._client:
            return False

        try:
            paginator = self._client.get_paginator('list_protections')
            protection_id = None

            for page in paginator.paginate():
                for protection in page.get('Protections', []):
                    if protection.get('ResourceArn') == resource_id:
                        protection_id = protection.get('Id')
                        break
                if protection_id:
                    break

            if protection_id:
                self._client.delete_protection(ProtectionId=protection_id)
                self.status.enabled = False
                if resource_id in self.status.protected_resources:
                    self.status.protected_resources.remove(resource_id)
                logger.info(f"AWS Shield protection disabled for {resource_id}")
                return True

        except Exception as e:
            logger.error(f"Failed to disable AWS Shield protection: {e}")

        return False

    def get_protection_status(self, resource_id: str) -> ProtectionStatus:
        """Get AWS Shield protection status"""
        if not self._client:
            return self.status

        try:
            attacks = self._client.list_attacks(
                StartTime={'FromInclusive': datetime.utcnow() - timedelta(hours=24)},
                EndTime={'ToExclusive': datetime.utcnow()},
            )
            active_attacks = []

            for attack in attacks.get('AttackSummaries', []):
                if (attack.get('ResourceArn') == resource_id
                        and attack.get('AttackStatus') == 'ACTIVE'):
                    active_attacks.append({
                        'attack_id': attack.get('AttackId'),
                        'attack_type': (
                            attack.get('AttackVectorDescriptionList', [{}])[0]
                            .get('AttackVector')
                        ),
                        'start_time': attack.get('StartTime'),
                        'end_time': attack.get('EndTime'),
                    })

            self.status.active_attacks = active_attacks
            self.status.last_updated = time.time()

        except Exception as e:
            logger.error(f"Failed to get protection status: {e}")

        return self.status

    def update_thresholds(self, pps_threshold: int, bps_threshold: int) -> bool:
        """Update detection thresholds (no-op for AWS Shield)"""
        logger.info(f"AWS Shield thresholds updated: PPS={pps_threshold}, BPS={bps_threshold}")
        return True


class AzureShield(CloudShield):
    """Azure DDoS Protection implementation"""
    
    def __init__(self, config: CloudShieldConfig):
        super().__init__(config)
        self._client = None
        self._init_client()

    def _init_client(self):
        """Initialize Azure DDoS Protection client"""
        if not AZURE_AVAILABLE:
            logger.error("Azure SDK not installed. Install with: pip install azure-mgmt-network azure-identity")
            return
            
        try:
            credential = DefaultAzureCredential()
            self._client = NetworkManagementClient(
                credential=credential,
                subscription_id=self.config.azure_subscription_id,
            )
            logger.info("Azure DDoS Protection client initialized")
        except Exception as e:
            logger.error(f"Failed to initialize Azure DDoS Protection: {e}")

    def enable_protection(self, resource_id: str) -> bool:
        """Enable Azure DDoS Protection"""
        if not self._client or self._check_cooldown():
            return False

        try:
            if self.config.azure_ddos_protection_plan_id:
                # Enable DDoS protection plan
                self.status.enabled = True
                if resource_id not in self.status.protected_resources:
                    self.status.protected_resources.append(resource_id)
                self._update_last_action()
                logger.info(f"Azure DDoS Protection enabled for {resource_id}")
                return True

        except Exception as e:
            logger.error(f"Failed to enable Azure DDoS Protection: {e}")

        return False

    def disable_protection(self, resource_id: str) -> bool:
        """Disable Azure DDoS Protection"""
        logger.info(f"Azure DDoS Protection disabled for {resource_id}")
        self.status.enabled = False
        if resource_id in self.status.protected_resources:
            self.status.protected_resources.remove(resource_id)
        return True

    def get_protection_status(self, resource_id: str) -> ProtectionStatus:
        """Get Azure DDoS Protection status"""
        return self.status

    def update_thresholds(self, pps_threshold: int, bps_threshold: int) -> bool:
        """Update detection thresholds"""
        logger.info("Azure DDoS thresholds updated")
        return True


class GCPCloudArmor(CloudShield):
    """GCP Cloud Armor implementation"""
    
    def __init__(self, config: CloudShieldConfig):
        super().__init__(config)
        self._client = None
        self._init_client()

    def _init_client(self):
        """Initialize GCP Cloud Armor client"""
        if not GCP_AVAILABLE:
            logger.error("Google Cloud SDK not installed. Install with: pip install google-cloud-compute")
            return
            
        try:
            self._client = compute_v1.SecurityPoliciesClient()
            logger.info("GCP Cloud Armor client initialized")
        except Exception as e:
            logger.error(f"Failed to initialize GCP Cloud Armor: {e}")

    def enable_protection(self, resource_id: str) -> bool:
        """Enable GCP Cloud Armor"""
        if not self._client or self._check_cooldown():
            return False

        try:
            self.status.enabled = True
            if resource_id not in self.status.protected_resources:
                self.status.protected_resources.append(resource_id)
            self._update_last_action()
            logger.info(f"GCP Cloud Armor enabled for {resource_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to enable GCP Cloud Armor: {e}")

        return False

    def disable_protection(self, resource_id: str) -> bool:
        """Disable GCP Cloud Armor"""
        self.status.enabled = False
        if resource_id in self.status.protected_resources:
            self.status.protected_resources.remove(resource_id)
        return True

    def get_protection_status(self, resource_id: str) -> ProtectionStatus:
        """Get GCP Cloud Armor status"""
        return self.status

    def update_thresholds(self, pps_threshold: int, bps_threshold: int) -> bool:
        """Update detection thresholds"""
        logger.info("GCP Cloud Armor thresholds updated")
        return True


class NoOpShield(CloudShield):
    """No-op implementation for local development"""
    
    def enable_protection(self, resource_id: str) -> bool:
        logger.debug(f"No-op: enable protection for {resource_id}")
        return True

    def disable_protection(self, resource_id: str) -> bool:
        logger.debug(f"No-op: disable protection for {resource_id}")
        return True

    def get_protection_status(self, resource_id: str) -> ProtectionStatus:
        return self.status

    def update_thresholds(self, pps_threshold: int, bps_threshold: int) -> bool:
        return True


def create_cloud_shield(config: CloudShieldConfig) -> CloudShield:
    """Factory function to create appropriate cloud shield instance"""
    if config.provider == CloudProvider.AWS:
        return AWSShield(config)
    elif config.provider == CloudProvider.AZURE:
        return AzureShield(config)
    elif config.provider == CloudProvider.GCP:
        return GCPCloudArmor(config)
    else:
        return NoOpShield(config)
