"""
Scrubber Redirect Module

Redirects attack traffic to DDoS scrubber centers using BGP FlowSpec
or GRE tunnels for traffic cleaning.
"""

import time
import logging
import subprocess
from collections import deque
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class RedirectStatus(Enum):
    """Status of traffic redirection"""
    INACTIVE = "inactive"
    REDIRECTING = "redirecting"
    SCRUBBING = "scrubbing"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class BGPFlowSpec:
    """BGP FlowSpec rule definition"""
    source_prefix: Optional[str] = None
    destination_prefix: str = ""
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[int] = None
    action: str = "redirect"
    redirect_next_hop: Optional[str] = None
    community: Optional[str] = None
    priority: int = 100

    def to_flow_spec_rule(self) -> Dict[str, Any]:
        """Convert to FlowSpec rule dictionary"""
        rule: Dict[str, Any] = {
            'action': self.action, 
            'priority': self.priority
        }
        if self.destination_prefix:
            rule['destination_prefix'] = self.destination_prefix
        if self.source_prefix:
            rule['source_prefix'] = self.source_prefix
        if self.redirect_next_hop:
            rule['redirect'] = self.redirect_next_hop
        if self.community:
            rule['community'] = self.community
        if self.protocol:
            rule['protocol'] = self.protocol
        if self.destination_port:
            rule['destination_port'] = self.destination_port
        if self.source_port:
            rule['source_port'] = self.source_port
        return rule


@dataclass
class ScrubberConfig:
    """Configuration for scrubber redirection"""
    enabled: bool = False

    # Scrubber endpoints
    scrubber_ipv4: Optional[str] = None
    scrubber_ipv6: Optional[str] = None
    scrubber_asn: Optional[int] = None

    # BGP configuration
    bgp_router_ip: Optional[str] = None
    bgp_asn: Optional[int] = None
    bgp_peer_ip: Optional[str] = None

    # Thresholds for redirection
    min_pps_threshold: int = 50_000
    min_bps_threshold: int = 1_000_000_000
    min_duration_seconds: int = 30

    # Auto-rollback settings
    auto_rollback: bool = True
    rollback_after_seconds: int = 3600


class ScrubberRedirect(ABC):
    """Abstract base class for scrubber redirection"""
    
    def __init__(self, config: ScrubberConfig):
        self.config = config
        self.status = RedirectStatus.INACTIVE
        self.active_redirects: Dict[str, BGPFlowSpec] = {}
        self.redirect_history: deque = deque(maxlen=1000)
        self.stats = {
            'redirects_initiated': 0,
            'redirects_completed': 0,
            'redirects_failed': 0,
            'current_redirects': 0,
            'total_traffic_scrubbed_gb': 0.0,
        }
        logger.info(f"ScrubberRedirect initialized with scrubber: {config.scrubber_ipv4}")

    @abstractmethod
    def inject_flow_spec(self, flow_spec: BGPFlowSpec) -> bool:
        """Inject FlowSpec rule"""
        pass

    @abstractmethod
    def withdraw_flow_spec(self, flow_spec: BGPFlowSpec) -> bool:
        """Withdraw FlowSpec rule"""
        pass

    def should_redirect(self, pps: float, bps: float, duration: float) -> bool:
        """Check if traffic should be redirected to scrubber"""
        if not self.config.enabled:
            return False

        volume_exceeded = (
            pps >= self.config.min_pps_threshold
            or bps >= self.config.min_bps_threshold
        )
        return volume_exceeded and duration >= self.config.min_duration_seconds

    def redirect_attack(self, target_ip: str, attack_details: Dict[str, Any]) -> bool:
        """Redirect attack traffic to scrubber"""
        if not self.config.scrubber_ipv4:
            logger.error("No scrubber IP configured")
            return False

        flow_spec = BGPFlowSpec(
            destination_prefix=f"{target_ip}/32",
            action="redirect",
            redirect_next_hop=self.config.scrubber_ipv4,
            community=f"{self.config.bgp_asn}:666" if self.config.bgp_asn else None,
            priority=100,
        )

        if self.inject_flow_spec(flow_spec):
            redirect_id = f"{target_ip}_{int(time.time())}"
            self.active_redirects[redirect_id] = flow_spec
            self.status = RedirectStatus.REDIRECTING
            self.stats['redirects_initiated'] += 1
            self.stats['current_redirects'] = len(self.active_redirects)

            self.redirect_history.append({
                'redirect_id': redirect_id,
                'target_ip': target_ip,
                'attack_details': attack_details,
                'started_at': time.time(),
                'status': 'active',
            })

            logger.info(
                f"Redirected traffic for {target_ip} to scrubber "
                f"{self.config.scrubber_ipv4}"
            )
            return True

        self.stats['redirects_failed'] += 1
        return False

    def rollback_redirect(self, target_ip: str) -> bool:
        """Rollback traffic redirection"""
        redirect_id = None
        flow_spec = None

        for rid, spec in self.active_redirects.items():
            if target_ip in spec.destination_prefix:
                redirect_id = rid
                flow_spec = spec
                break

        if not flow_spec:
            logger.warning(f"No active redirect found for {target_ip}")
            return False

        if self.withdraw_flow_spec(flow_spec):
            del self.active_redirects[redirect_id]
            self.stats['redirects_completed'] += 1
            self.stats['current_redirects'] = len(self.active_redirects)

            for record in self.redirect_history:
                if record.get('redirect_id') == redirect_id:
                    record['ended_at'] = time.time()
                    record['status'] = 'completed'
                    break

            logger.info(f"Rolled back traffic redirection for {target_ip}")
            return True

        return False

    def rollback_expired_redirects(self):
        """Rollback expired redirects"""
        if not self.config.auto_rollback:
            return

        now = time.time()
        for redirect_id, flow_spec in list(self.active_redirects.items()):
            start_time = None
            for record in self.redirect_history:
                if record.get('redirect_id') == redirect_id:
                    start_time = record.get('started_at')
                    break

            if start_time and (now - start_time) > self.config.rollback_after_seconds:
                target_ip = flow_spec.destination_prefix.replace('/32', '')
                self.rollback_redirect(target_ip)

    def get_active_redirects(self) -> List[Dict[str, Any]]:
        """Get list of active redirects"""
        return [
            {
                'target_ip': spec.destination_prefix.replace('/32', ''),
                'redirect_next_hop': spec.redirect_next_hop,
                'priority': spec.priority,
            }
            for spec in self.active_redirects.values()
        ]

    def get_stats(self) -> Dict[str, Any]:
        """Get scrubber statistics"""
        return {
            **self.stats,
            'status': self.status.value,
            'active_redirects': len(self.active_redirects),
            'enabled': self.config.enabled,
            'scrubber_ip': self.config.scrubber_ipv4,
        }


class BGPFlowSpecRedirect(ScrubberRedirect):
    """BGP FlowSpec-based traffic redirection"""
    
    def __init__(self, config: ScrubberConfig):
        super().__init__(config)
        self._bgp_session = None
        self._init_bgp()

    def _init_bgp(self):
        """Initialize BGP session"""
        if self.config.bgp_router_ip:
            logger.info(
                f"BGP session configured: router={self.config.bgp_router_ip}, "
                f"ASN={self.config.bgp_asn}"
            )

    def inject_flow_spec(self, flow_spec: BGPFlowSpec) -> bool:
        """Inject BGP FlowSpec rule"""
        try:
            rule = flow_spec.to_flow_spec_rule()
            logger.info(f"Injecting FlowSpec: {rule}")
            # In production, this would use ExaBGP or similar BGP implementation
            return True
        except Exception as e:
            logger.error(f"Failed to inject FlowSpec: {e}")
            return False

    def withdraw_flow_spec(self, flow_spec: BGPFlowSpec) -> bool:
        """Withdraw BGP FlowSpec rule"""
        try:
            logger.info(f"Withdrawing FlowSpec for {flow_spec.destination_prefix}")
            # In production, this would use ExaBGP or similar BGP implementation
            return True
        except Exception as e:
            logger.error(f"Failed to withdraw FlowSpec: {e}")
            return False


class GREOverlayRedirect(ScrubberRedirect):
    """GRE tunnel-based traffic redirection"""
    
    def __init__(self, config: ScrubberConfig):
        super().__init__(config)
        self.gre_tunnels: Dict[str, str] = {}

    def _create_gre_tunnel(self, target_ip: str) -> bool:
        """Create GRE tunnel to scrubber"""
        tunnel_name = f"gre_scrubber_{target_ip.replace('.', '_')}"

        if not self.config.scrubber_ipv4 or not self.config.bgp_router_ip:
            logger.error("scrubber_ipv4 and bgp_router_ip must be configured")
            return False

        try:
            commands = [
                ["ip", "tunnel", "add", tunnel_name, "mode", "gre",
                 "remote", self.config.scrubber_ipv4,
                 "local", self.config.bgp_router_ip, "ttl", "255"],
                ["ip", "link", "set", tunnel_name, "up"],
                ["ip", "route", "add", f"{target_ip}/32", "dev", tunnel_name],
            ]

            for argv in commands:
                subprocess.run(argv, shell=False, check=True, capture_output=True, timeout=10)

            self.gre_tunnels[target_ip] = tunnel_name
            logger.info(f"Created GRE tunnel {tunnel_name} for {target_ip}")
            return True

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to create GRE tunnel: {e.stderr if e.stderr else str(e)}")
            return False
        except Exception as e:
            logger.error(f"Failed to create GRE tunnel: {e}")
            return False

    def _delete_gre_tunnel(self, target_ip: str) -> bool:
        """Delete GRE tunnel"""
        if target_ip not in self.gre_tunnels:
            return False

        tunnel_name = self.gre_tunnels[target_ip]

        try:
            commands = [
                ["ip", "route", "del", f"{target_ip}/32"],
                ["ip", "link", "set", tunnel_name, "down"],
                ["ip", "tunnel", "del", tunnel_name],
            ]

            for argv in commands:
                subprocess.run(argv, shell=False, check=True, capture_output=True, timeout=10)

            del self.gre_tunnels[target_ip]
            logger.info(f"Deleted GRE tunnel {tunnel_name}")
            return True

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to delete GRE tunnel: {e.stderr if e.stderr else str(e)}")
            return False
        except Exception as e:
            logger.error(f"Failed to delete GRE tunnel: {e}")
            return False

    def inject_flow_spec(self, flow_spec: BGPFlowSpec) -> bool:
        """Inject GRE tunnel for traffic redirection"""
        target_ip = flow_spec.destination_prefix.replace('/32', '')
        return self._create_gre_tunnel(target_ip)

    def withdraw_flow_spec(self, flow_spec: BGPFlowSpec) -> bool:
        """Withdraw GRE tunnel"""
        target_ip = flow_spec.destination_prefix.replace('/32', '')
        return self._delete_gre_tunnel(target_ip)


def create_scrubber_redirect(config: ScrubberConfig, method: str = "bgp") -> ScrubberRedirect:
    """Factory function to create scrubber redirect instance"""
    if method == "bgp":
        return BGPFlowSpecRedirect(config)
    elif method == "gre":
        return GREOverlayRedirect(config)
    else:
        raise ValueError(f"Unknown scrubber method: {method}")