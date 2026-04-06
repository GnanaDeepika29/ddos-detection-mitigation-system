"""
Scrubber Redirect Module

Redirects attack traffic to DDoS scrubber centers using BGP FlowSpec
or GRE tunnels for traffic cleaning.
"""

import subprocess
import time
import logging
from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class RedirectStatus(Enum):
    INACTIVE = "inactive"
    REDIRECTING = "redirecting"
    SCRUBBING = "scrubbing"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class BGPFlowSpec:
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
        rule: Dict[str, Any] = {'action': self.action, 'priority': self.priority}
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
    enabled: bool = False
    scrubber_ipv4: Optional[str] = None
    scrubber_ipv6: Optional[str] = None
    scrubber_asn: Optional[int] = None
    bgp_router_ip: Optional[str] = None
    bgp_asn: Optional[int] = None
    bgp_peer_ip: Optional[str] = None
    min_pps_threshold: int = 50_000
    min_bps_threshold: int = 1_000_000_000
    min_duration_seconds: int = 30
    auto_rollback: bool = True
    rollback_after_seconds: int = 3_600


# ---------------------------------------------------------------------------
# Internal bookkeeping for active redirects
# ---------------------------------------------------------------------------

@dataclass
class _RedirectEntry:
    """Combines FlowSpec rule with tracking metadata."""
    flow_spec: BGPFlowSpec
    target_ip: str
    started_at: float = field(default_factory=time.time)


class ScrubberRedirect(ABC):
    """Abstract base class for scrubber redirection."""

    def __init__(self, config: ScrubberConfig) -> None:
        self.config = config
        self.status = RedirectStatus.INACTIVE
        # FIX BUG-19: active_redirects now stores _RedirectEntry (flow_spec +
        # started_at) rather than just the BGPFlowSpec.  This eliminates the
        # O(n×m) deque search and avoids the bug where start_time is lost if
        # the entry aged out of redirect_history.
        self.active_redirects: Dict[str, _RedirectEntry] = {}
        self.redirect_history: deque = deque(maxlen=1_000)
        self.stats: Dict[str, Any] = {
            'redirects_initiated': 0,
            'redirects_completed': 0,
            'redirects_failed': 0,
            'current_redirects': 0,
            'total_traffic_scrubbed_gb': 0.0,
        }
        logger.info(f"ScrubberRedirect initialised (scrubber: {config.scrubber_ipv4})")

    @abstractmethod
    def inject_flow_spec(self, flow_spec: BGPFlowSpec) -> bool: ...

    @abstractmethod
    def withdraw_flow_spec(self, flow_spec: BGPFlowSpec) -> bool: ...

    def should_redirect(self, pps: float, bps: float, duration: float) -> bool:
        if not self.config.enabled:
            return False
        volume_exceeded = (
            pps >= self.config.min_pps_threshold
            or bps >= self.config.min_bps_threshold
        )
        return volume_exceeded and duration >= self.config.min_duration_seconds

    def redirect_attack(self, target_ip: str, attack_details: Dict[str, Any]) -> bool:
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
            # FIX BUG-19: store entry with start_time embedded.
            self.active_redirects[redirect_id] = _RedirectEntry(
                flow_spec=flow_spec,
                target_ip=target_ip,
            )
            self.status = RedirectStatus.REDIRECTING
            self.stats['redirects_initiated'] += 1
            self.stats['current_redirects'] = len(self.active_redirects)

            self.redirect_history.append({
                'redirect_id': redirect_id,
                'target_ip': target_ip,
                'attack_details': attack_details,
                'started_at': self.active_redirects[redirect_id].started_at,
                'status': 'active',
            })

            logger.info(
                f"Redirected {target_ip} → scrubber {self.config.scrubber_ipv4}"
            )
            return True

        self.stats['redirects_failed'] += 1
        return False

    def rollback_redirect(self, target_ip: str) -> bool:
        """
        Rollback traffic redirection for a specific target IP.

        FIX BUG-18: The original used `target_ip in spec.destination_prefix`
        (substring match).  A partial IP like "1.2.3" would incorrectly match
        "1.2.3.4/32".  Now uses an exact prefix comparison.
        """
        redirect_id: Optional[str] = None
        entry: Optional[_RedirectEntry] = None

        for rid, e in self.active_redirects.items():
            # FIX BUG-18: exact match against the canonical "ip/32" form.
            if e.flow_spec.destination_prefix == f"{target_ip}/32":
                redirect_id = rid
                entry = e
                break

        if not entry or not redirect_id:
            logger.warning(f"No active redirect found for {target_ip}")
            return False

        if self.withdraw_flow_spec(entry.flow_spec):
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

    def rollback_expired_redirects(self) -> None:
        """
        Roll back redirects that have exceeded rollback_after_seconds.

        FIX BUG-19: start_time is now stored directly in _RedirectEntry
        so this method runs in O(n) rather than O(n×m) and is immune to
        history deque eviction.
        """
        if not self.config.auto_rollback:
            return

        now = time.time()
        for rid, entry in list(self.active_redirects.items()):
            if now - entry.started_at > self.config.rollback_after_seconds:
                self.rollback_redirect(entry.target_ip)

    def get_active_redirects(self) -> List[Dict[str, Any]]:
        return [
            {
                'target_ip': entry.target_ip,
                'redirect_next_hop': entry.flow_spec.redirect_next_hop,
                'priority': entry.flow_spec.priority,
                'started_at': entry.started_at,
            }
            for entry in self.active_redirects.values()
        ]

    def get_stats(self) -> Dict[str, Any]:
        return {
            **self.stats,
            'status': self.status.value,
            'active_redirects': len(self.active_redirects),
            'enabled': self.config.enabled,
            'scrubber_ip': self.config.scrubber_ipv4,
        }


class BGPFlowSpecRedirect(ScrubberRedirect):
    """BGP FlowSpec-based traffic redirection."""

    def __init__(self, config: ScrubberConfig) -> None:
        super().__init__(config)
        self._init_bgp()

    def _init_bgp(self) -> None:
        if self.config.bgp_router_ip:
            logger.info(
                f"BGP session configured: router={self.config.bgp_router_ip}, "
                f"ASN={self.config.bgp_asn}"
            )

    def inject_flow_spec(self, flow_spec: BGPFlowSpec) -> bool:
        try:
            rule = flow_spec.to_flow_spec_rule()
            logger.info(f"Injecting FlowSpec: {rule}")
            return True
        except Exception as exc:
            logger.error(f"Failed to inject FlowSpec: {exc}")
            return False

    def withdraw_flow_spec(self, flow_spec: BGPFlowSpec) -> bool:
        try:
            logger.info(f"Withdrawing FlowSpec for {flow_spec.destination_prefix}")
            return True
        except Exception as exc:
            logger.error(f"Failed to withdraw FlowSpec: {exc}")
            return False


class GREOverlayRedirect(ScrubberRedirect):
    """GRE tunnel-based traffic redirection."""

    def __init__(self, config: ScrubberConfig) -> None:
        super().__init__(config)
        self.gre_tunnels: Dict[str, str] = {}

    def _create_gre_tunnel(self, target_ip: str) -> bool:
        """
        Create a GRE tunnel to redirect traffic for target_ip.

        FIX BUG-20: The original used check=True on each subprocess.run
        command in sequence.  If command 1 succeeded but command 2 raised
        CalledProcessError, the tunnel interface was left orphaned (created
        but never recorded in self.gre_tunnels → never cleaned up).
        Now we track partial success and attempt cleanup on failure.
        """
        tunnel_name = f"gre_scrubber_{target_ip.replace('.', '_')}"

        if not self.config.scrubber_ipv4 or not self.config.bgp_router_ip:
            logger.error("scrubber_ipv4 and bgp_router_ip must be configured")
            return False

        commands = [
            ["ip", "tunnel", "add", tunnel_name, "mode", "gre",
             "remote", self.config.scrubber_ipv4,
             "local", self.config.bgp_router_ip, "ttl", "255"],
            ["ip", "link", "set", tunnel_name, "up"],
            ["ip", "route", "add", f"{target_ip}/32", "dev", tunnel_name],
        ]

        executed: List[int] = []   # indices of successfully run commands
        success = True

        for idx, argv in enumerate(commands):
            try:
                subprocess.run(
                    argv, shell=False, check=True,
                    capture_output=True, timeout=10,
                )
                executed.append(idx)
            except subprocess.CalledProcessError as exc:
                logger.error(
                    f"GRE tunnel setup failed at step {idx}: "
                    f"{exc.stderr.decode() if exc.stderr else str(exc)}"
                )
                success = False
                break
            except Exception as exc:
                logger.error(f"GRE tunnel setup failed at step {idx}: {exc}")
                success = False
                break

        if not success:
            # FIX BUG-20: attempt partial cleanup so the tunnel isn't orphaned.
            self._cleanup_partial_tunnel(tunnel_name, executed)
            return False

        self.gre_tunnels[target_ip] = tunnel_name
        logger.info(f"Created GRE tunnel {tunnel_name} for {target_ip}")
        return True

    def _cleanup_partial_tunnel(
        self, tunnel_name: str, executed_steps: List[int]
    ) -> None:
        """Best-effort cleanup of a partially created GRE tunnel."""
        cleanup_cmds = [
            ["ip", "link", "set", tunnel_name, "down"],
            ["ip", "tunnel", "del", tunnel_name],
        ]
        for argv in cleanup_cmds:
            try:
                subprocess.run(
                    argv, shell=False, capture_output=True, timeout=5
                )
            except Exception:
                pass

    def _delete_gre_tunnel(self, target_ip: str) -> bool:
        if target_ip not in self.gre_tunnels:
            return False

        tunnel_name = self.gre_tunnels[target_ip]
        commands = [
            ["ip", "route", "del", f"{target_ip}/32"],
            ["ip", "link", "set", tunnel_name, "down"],
            ["ip", "tunnel", "del", tunnel_name],
        ]

        success = True
        for argv in commands:
            try:
                subprocess.run(
                    argv, shell=False, check=True,
                    capture_output=True, timeout=10,
                )
            except subprocess.CalledProcessError as exc:
                logger.error(
                    f"Failed to delete GRE tunnel: "
                    f"{exc.stderr.decode() if exc.stderr else str(exc)}"
                )
                success = False
            except Exception as exc:
                logger.error(f"Failed to delete GRE tunnel: {exc}")
                success = False

        if success:
            del self.gre_tunnels[target_ip]
            logger.info(f"Deleted GRE tunnel {tunnel_name}")

        return success

    def inject_flow_spec(self, flow_spec: BGPFlowSpec) -> bool:
        target_ip = flow_spec.destination_prefix.replace('/32', '')
        return self._create_gre_tunnel(target_ip)

    def withdraw_flow_spec(self, flow_spec: BGPFlowSpec) -> bool:
        target_ip = flow_spec.destination_prefix.replace('/32', '')
        return self._delete_gre_tunnel(target_ip)


def create_scrubber_redirect(
    config: ScrubberConfig, method: str = "bgp"
) -> ScrubberRedirect:
    if method == "bgp":
        return BGPFlowSpecRedirect(config)
    if method == "gre":
        return GREOverlayRedirect(config)
    raise ValueError(f"Unknown scrubber method: {method!r}")