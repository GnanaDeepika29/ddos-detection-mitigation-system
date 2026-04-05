"""
Rule Injection Module

Injects firewall rules into the local system using iptables or nftables.
"""

import re
import subprocess
import time
import logging
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List, Tuple
from threading import RLock

logger = logging.getLogger(__name__)

_SAFE_IP_RE = re.compile(r'^[\d.:/a-fA-F]+$')


def _validate_ip(value: str) -> str:
    """Validate IP address format to prevent command injection"""
    if not _SAFE_IP_RE.fullmatch(value):
        raise ValueError(f"Unsafe IP/subnet value rejected: {value!r}")
    return value


class FirewallType(Enum):
    """Supported firewall types"""
    IPTABLES = "iptables"
    NFTABLES = "nftables"
    AUTO = "auto"


class RuleAction(Enum):
    """Firewall rule actions"""
    DROP = "DROP"
    REJECT = "REJECT"
    ACCEPT = "ACCEPT"
    LIMIT = "LIMIT"


@dataclass
class FirewallRule:
    """Represents a firewall rule"""
    id: str
    action: RuleAction
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    protocol: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    limit_rate: Optional[str] = None
    limit_burst: Optional[int] = None
    created_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None
    reason: str = ""
    nft_handle: Optional[int] = None

    def to_iptables(self, chain: str = "INPUT") -> List[List[str]]:
        """Convert rule to iptables commands"""
        # Validate IPs before building commands
        if self.source_ip:
            _validate_ip(self.source_ip)
        if self.destination_ip:
            _validate_ip(self.destination_ip)

        base = ["iptables", "-A", chain]

        if self.source_ip:
            base += ["-s", self.source_ip]
        if self.destination_ip:
            base += ["-d", self.destination_ip]
        if self.protocol:
            base += ["-p", self.protocol]

        # Port matching requires protocol specification
        if self.source_port or self.destination_port:
            proto = self.protocol or "tcp"
            if not self.protocol:
                base += ["-p", proto]
            base += ["-m", proto]
            if self.source_port:
                base += ["--sport", str(self.source_port)]
            if self.destination_port:
                base += ["--dport", str(self.destination_port)]

        # Rate limiting
        if self.limit_rate:
            allow = list(base) + ["-m", "limit", "--limit", self.limit_rate]
            if self.limit_burst:
                allow += ["--limit-burst", str(self.limit_burst)]
            allow += ["-j", "ACCEPT"]

            drop = list(base) + ["-j", "DROP"]
            return [allow, drop]

        base += ["-j", self.action.value]
        return [base]

    def to_nftables(self, table: str = "filter", chain: str = "input") -> List[List[str]]:
        """Convert rule to nftables commands"""
        # Validate IPs before building commands
        if self.source_ip:
            _validate_ip(self.source_ip)
        if self.destination_ip:
            _validate_ip(self.destination_ip)

        parts = ["nft", "add", "rule", table, chain]

        if self.source_ip:
            parts += ["ip", "saddr", self.source_ip]
        if self.destination_ip:
            parts += ["ip", "daddr", self.destination_ip]
        if self.protocol:
            parts.append(self.protocol)
        if self.source_port:
            parts += ["sport", str(self.source_port)]
        if self.destination_port:
            parts += ["dport", str(self.destination_port)]

        # Rate limiting for nftables
        if self.limit_rate:
            # Convert "1000/sec" to nftables format
            rate_value = self.limit_rate.replace('/sec', '')
            parts += ["limit", f"rate {rate_value}"]
            if self.limit_burst:
                parts += ["burst", str(self.limit_burst)]

        parts.append(self.action.value.lower())
        return [parts]

    def is_expired(self) -> bool:
        """Check if rule has expired"""
        return bool(self.expires_at and time.time() > self.expires_at)


@dataclass
class RuleInjectorConfig:
    """Configuration for rule injector"""
    firewall_type: FirewallType = FirewallType.AUTO
    default_chain: str = "INPUT"
    default_table: str = "filter"
    enable_rollback: bool = True
    max_rules: int = 1000
    default_ttl_seconds: int = 3600
    require_sudo: bool = True


class RuleInjector:
    """Injects firewall rules for DDoS mitigation"""
    
    def __init__(self, config: Optional[RuleInjectorConfig] = None):
        self.config = config or RuleInjectorConfig()
        self.active_rules: Dict[str, FirewallRule] = {}
        self.rule_counter = 0
        self.lock = RLock()
        self._detect_firewall()
        self.stats = {
            'rules_added': 0, 
            'rules_removed': 0, 
            'rules_expired': 0, 
            'errors': 0, 
            'active_rules': 0
        }
        logger.info(f"RuleInjector initialized with firewall: {self.config.firewall_type.value}")

    def _detect_firewall(self):
        """Auto-detect available firewall"""
        if self.config.firewall_type != FirewallType.AUTO:
            return

        for fw_type, cmd in [
            (FirewallType.IPTABLES, ["iptables", "--version"]),
            (FirewallType.NFTABLES, ["nft", "--version"])
        ]:
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
                if result.returncode == 0:
                    self.config.firewall_type = fw_type
                    logger.info(f"Auto-detected {fw_type.value}")
                    return
            except (subprocess.SubprocessError, FileNotFoundError):
                pass

        logger.warning("No firewall backend detected, defaulting to iptables")
        self.config.firewall_type = FirewallType.IPTABLES

    def _run_command(self, argv: List[str]) -> Tuple[bool, str]:
        """Run a shell command safely"""
        try:
            if self.config.require_sudo and argv[0] != "sudo":
                argv = ["sudo"] + argv

            result = subprocess.run(
                argv, 
                shell=False, 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            if result.returncode == 0:
                return True, result.stdout
            else:
                return False, result.stderr
        except subprocess.TimeoutExpired:
            return False, "Command timed out"
        except Exception as e:
            return False, str(e)

    def _generate_rule_id(self) -> str:
        """Generate unique rule ID"""
        self.rule_counter += 1
        return f"ddos_mitigation_{int(time.time())}_{self.rule_counter}"

    def _remove_rule_unlocked(self, rule_id: str) -> bool:
        """Remove rule (caller must hold lock)"""
        if rule_id not in self.active_rules:
            return False

        rule = self.active_rules[rule_id]

        if self.config.firewall_type == FirewallType.IPTABLES:
            add_commands = rule.to_iptables(self.config.default_chain)
            # Convert add commands to delete commands
            del_commands = []
            for cmd in add_commands:
                del_cmd = ["-D" if arg == "-A" else arg for arg in cmd]
                del_commands.append(del_cmd)
        elif self.config.firewall_type == FirewallType.NFTABLES:
            if rule.nft_handle is None:
                logger.error(f"No nft handle for rule {rule_id}")
                return False
            del_commands = [[
                "nft", "delete", "rule", self.config.default_table,
                self.config.default_chain, "handle", str(rule.nft_handle)
            ]]
        else:
            return False

        success = True
        for argv in del_commands:
            ok, output = self._run_command(argv)
            if not ok:
                logger.error(f"Failed to remove rule {rule_id}: {output}")
                success = False
                self.stats['errors'] += 1

        if success:
            del self.active_rules[rule_id]
            self.stats['rules_removed'] += 1
            self.stats['active_rules'] = len(self.active_rules)
            logger.info(f"Removed rule {rule_id}")

        return success

    def add_rule(self, rule: FirewallRule) -> bool:
        """Add a firewall rule"""
        with self.lock:
            # Check rule limit
            if len(self.active_rules) >= self.config.max_rules:
                self._remove_oldest_rules()

            # Generate ID if not provided
            rule.id = rule.id or self._generate_rule_id()

            # Set expiration if not set
            if rule.expires_at is None and self.config.default_ttl_seconds > 0:
                rule.expires_at = time.time() + self.config.default_ttl_seconds

            # Generate commands based on firewall type
            if self.config.firewall_type == FirewallType.IPTABLES:
                commands = rule.to_iptables(self.config.default_chain)
            elif self.config.firewall_type == FirewallType.NFTABLES:
                commands = rule.to_nftables(self.config.default_table, self.config.default_chain)
            else:
                return False

            # Execute commands
            success = True
            for argv in commands:
                ok, output = self._run_command(argv)
                if not ok:
                    logger.error(f"Failed to add rule: {argv}\nError: {output}")
                    success = False
                    self.stats['errors'] += 1
                    break
                    
                # Extract nftables handle if applicable
                if self.config.firewall_type == FirewallType.NFTABLES:
                    handle_match = re.search(r'# handle (\d+)', output)
                    if handle_match:
                        rule.nft_handle = int(handle_match.group(1))

            if success:
                self.active_rules[rule.id] = rule
                self.stats['rules_added'] += 1
                self.stats['active_rules'] = len(self.active_rules)
                logger.info(f"Added rule {rule.id}: {rule.action.value} {rule.source_ip or 'any'}")
                return True

            return False

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a firewall rule by ID"""
        with self.lock:
            return self._remove_rule_unlocked(rule_id)

    def _remove_oldest_rules(self):
        """Remove oldest rules when limit is reached"""
        if not self.active_rules:
            return

        sorted_rules = sorted(self.active_rules.items(), key=lambda x: x[1].created_at)
        remove_count = max(1, int(len(self.active_rules) * 0.1))

        for rule_id, _ in sorted_rules[:remove_count]:
            self._remove_rule_unlocked(rule_id)

        logger.info(f"Removed {remove_count} oldest rules due to limit")

    def block_ip(self, ip_address: str, duration_seconds: Optional[int] = None, reason: str = "") -> Optional[str]:
        """Block an IP address"""
        _validate_ip(ip_address)
        rule = FirewallRule(
            id="", 
            action=RuleAction.DROP, 
            source_ip=ip_address,
            reason=reason or f"DDoS mitigation: block IP {ip_address}",
            expires_at=time.time() + (duration_seconds or self.config.default_ttl_seconds),
        )
        return rule.id if self.add_rule(rule) else None

    def rate_limit_ip(self, ip_address: str, rate: str = "1000/sec", burst: int = 2000,
                      duration_seconds: Optional[int] = None) -> Optional[str]:
        """Rate limit an IP address"""
        _validate_ip(ip_address)
        rule = FirewallRule(
            id="", 
            action=RuleAction.LIMIT, 
            source_ip=ip_address,
            limit_rate=rate, 
            limit_burst=burst,
            reason=f"DDoS mitigation: rate limit {ip_address} to {rate}",
            expires_at=time.time() + (duration_seconds or self.config.default_ttl_seconds),
        )
        return rule.id if self.add_rule(rule) else None

    def expire_rules(self):
        """Remove expired rules"""
        with self.lock:
            now = time.time()
            expired = [
                rid for rid, rule in self.active_rules.items()
                if rule.expires_at and rule.expires_at <= now
            ]
            for rule_id in expired:
                if self._remove_rule_unlocked(rule_id):
                    self.stats['rules_expired'] += 1

        if expired:
            logger.info(f"Expired {len(expired)} rules")

    def get_active_rules(self) -> List[Dict[str, Any]]:
        """Get list of active rules"""
        return [
            {
                'id': rid, 
                'action': rule.action.value, 
                'source_ip': rule.source_ip,
                'destination_ip': rule.destination_ip,
                'protocol': rule.protocol,
                'expires_at': rule.expires_at, 
                'reason': rule.reason,
                'created_at': rule.created_at,
            }
            for rid, rule in self.active_rules.items()
        ]

    def clear_all_rules(self) -> int:
        """Clear all active rules"""
        count = len(self.active_rules)
        for rule_id in list(self.active_rules.keys()):
            self.remove_rule(rule_id)
        return count

    def get_stats(self) -> Dict[str, Any]:
        """Get injector statistics"""
        return {
            **self.stats, 
            'firewall_type': self.config.firewall_type.value, 
            'max_rules': self.config.max_rules
        }
