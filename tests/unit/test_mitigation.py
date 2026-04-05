"""
Unit Tests for Mitigation Module

Tests for rule injection, cloud shield integration, scrubber redirect, and rate limiting.
"""

import pytest
import time
import json
from unittest.mock import Mock, patch, MagicMock, call

from src.mitigation.rule_injector import (
    RuleInjector, RuleInjectorConfig, FirewallType, FirewallRule, RuleAction
)
from src.mitigation.cloud_shield import (
    CloudShield, CloudShieldConfig, CloudProvider, ShieldAction, create_cloud_shield
)
from src.mitigation.scrubber_redirect import (
    ScrubberRedirect, ScrubberConfig, BGPFlowSpec, RedirectStatus,
    BGPFlowSpecRedirect, GREOverlayRedirect
)
from src.mitigation.rate_limiter import (
    RateLimiter, RateLimiterConfig, LimitType, RateLimitRule, TokenBucket
)


class TestRuleInjector:

    def setup_method(self):
        self.config = RuleInjectorConfig(
            firewall_type=FirewallType.IPTABLES,
            default_chain="INPUT",
            default_ttl_seconds=3600,
            require_sudo=False,
        )
        self.injector = RuleInjector(self.config)

    @patch('subprocess.run')
    def test_add_iptables_rule(self, mock_run):
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        rule = FirewallRule(
            id="",
            action=RuleAction.DROP,
            source_ip="192.168.1.100",
            reason="Block malicious IP",
        )

        result = self.injector.add_rule(rule)

        assert result is True
        assert len(self.injector.active_rules) == 1
        assert self.injector.stats['rules_added'] == 1

    @patch('subprocess.run')
    def test_block_ip(self, mock_run):
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        rule_id = self.injector.block_ip("10.0.0.1", reason="DDoS attack")

        assert rule_id is not None
        assert rule_id in self.injector.active_rules

        rule = self.injector.active_rules[rule_id]
        assert rule.action == RuleAction.DROP
        assert rule.source_ip == "10.0.0.1"

    @patch('subprocess.run')
    def test_rate_limit_ip(self, mock_run):
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        rule_id = self.injector.rate_limit_ip(
            "192.168.1.100",
            rate="1000/sec",
            burst=2000,
        )

        assert rule_id is not None
        rule = self.injector.active_rules[rule_id]
        assert rule.action == RuleAction.LIMIT
        assert rule.limit_rate == "1000/sec"
        assert mock_run.call_count == 2
        first_call = mock_run.call_args_list[0][0][0]
        second_call = mock_run.call_args_list[1][0][0]
        assert first_call[-2:] == ['-j', 'ACCEPT']
        assert second_call[-2:] == ['-j', 'DROP']

    @patch('subprocess.run')
    def test_remove_rule(self, mock_run):
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        rule_id = self.injector.block_ip("10.0.0.1")
        assert len(self.injector.active_rules) == 1

        result = self.injector.remove_rule(rule_id)

        assert result is True
        assert len(self.injector.active_rules) == 0
        assert self.injector.stats['rules_removed'] == 1

    def test_rule_expiration(self):
        rule = FirewallRule(
            id="test_rule",
            action=RuleAction.DROP,
            source_ip="192.168.1.1",
            expires_at=time.time() - 10,
        )

        self.injector.active_rules["test_rule"] = rule

        with patch.object(self.injector, '_run_command', return_value=(True, "")):
            self.injector.expire_rules()

        assert "test_rule" not in self.injector.active_rules
        assert self.injector.stats['rules_expired'] == 1


class TestTokenBucket:

    def test_token_consumption(self):
        bucket = TokenBucket(rate=100, burst=100)

        assert bucket.get_tokens() == 100

        assert bucket.consume(50) is True
        assert bucket.get_tokens() == 50

        assert bucket.consume(60) is False
        assert bucket.get_tokens() == 50

    def test_token_refill(self):
        bucket = TokenBucket(rate=100, burst=100)

        bucket.consume(100)
        assert bucket.get_tokens() == 0

        time.sleep(0.5)

        tokens = bucket.get_tokens()
        assert 40 <= tokens <= 60


class TestRateLimiter:

    def setup_method(self):
        self.config = RateLimiterConfig(
            default_packet_rate=1000,
            default_byte_rate=1048576,
            enable_auto_rules=True,
            use_sliding_window=False,
            rule_cleanup_interval=1,
        )
        self.limiter = RateLimiter(self.config)

    def teardown_method(self):
        self.limiter.stop()

    def test_add_rate_limit_rule(self):
        rule_id = self.limiter.rate_limit_ip("192.168.1.100", rate_pps=500)

        assert rule_id is not None
        assert len(self.limiter.rules) == 1
        assert self.limiter.stats['rules_created'] == 1

    def test_rate_limit_check_allowed(self):
        self.limiter.rate_limit_ip("192.168.1.100", rate_pps=100)

        for _ in range(100):
            assert self.limiter.check_rate_limit("192.168.1.100", packets=1) is True

        assert self.limiter.check_rate_limit("192.168.1.100", packets=1) is False

    def test_rate_limit_different_ips(self):
        self.limiter.rate_limit_ip("192.168.1.100", rate_pps=10)

        for _ in range(10):
            self.limiter.check_rate_limit("192.168.1.100", packets=1)

        assert self.limiter.check_rate_limit("192.168.2.100", packets=1) is True

    def test_rule_expiration(self):
        rule_id = self.limiter.rate_limit_ip("192.168.1.100", rate_pps=100, duration_seconds=1)

        assert rule_id in self.limiter.rules

        time.sleep(1.5)
        self.limiter._cleanup_expired_rules()

        assert rule_id not in self.limiter.rules

    def test_stats_tracking(self):
        self.limiter.rate_limit_ip("192.168.1.100", rate_pps=10)

        for _ in range(15):
            self.limiter.check_rate_limit("192.168.1.100", packets=1)

        stats = self.limiter.get_stats()
        assert stats['packets_allowed'] == 10
        assert stats['packets_limited'] == 5
        assert stats['active_rules'] == 1


class TestCloudShield:

    def setup_method(self):
        self.config = CloudShieldConfig(
            provider=CloudProvider.NONE,
            auto_enable=True,
        )

    def test_noop_shield(self):
        shield = create_cloud_shield(self.config)

        assert shield.enable_protection("test-resource") is True
        assert shield.disable_protection("test-resource") is True

        status = shield.get_protection_status("test-resource")
        assert status.enabled is False

    @patch('src.mitigation.cloud_shield.boto3.client')
    def test_aws_shield_enable(self, mock_client):
        mock_shield = Mock()
        mock_shield.create_protection.return_value = {'ProtectionId': 'prot-123'}
        mock_client.return_value = mock_shield

        config = CloudShieldConfig(
            provider=CloudProvider.AWS,
            aws_region="us-east-1",
            cooldown_seconds=0,
        )

        shield = create_cloud_shield(config)
        shield._client = mock_shield

        result = shield.enable_protection("arn:aws:resource:123")

        assert result is True
        assert shield.status.enabled is True


class TestScrubberRedirect:

    def setup_method(self):
        self.config = ScrubberConfig(
            enabled=True,
            scrubber_ipv4="203.0.113.1",
            bgp_asn=65000,
            min_pps_threshold=10000,
            min_duration_seconds=30,
            auto_rollback=True,
            rollback_after_seconds=60,
        )

    def test_should_redirect(self):
        redirector = BGPFlowSpecRedirect(self.config)

        # Below volume threshold
        assert redirector.should_redirect(pps=5000, bps=1000000, duration=60) is False

        # Above PPS but duration too short
        assert redirector.should_redirect(pps=20000, bps=1000000, duration=10) is False

        # Above PPS and duration met
        assert redirector.should_redirect(pps=20000, bps=1000000, duration=30) is True

        # Above BPS and duration met
        assert redirector.should_redirect(pps=5000, bps=2000000000, duration=30) is True

    def test_bgp_flow_spec_creation(self):
        flow_spec = BGPFlowSpec(
            destination_prefix="10.0.0.1/32",
            action="redirect",
            redirect_next_hop="203.0.113.1",
            community="65000:666",
            priority=100,
        )

        rule = flow_spec.to_flow_spec_rule()

        assert rule['action'] == 'redirect'
        assert rule['destination_prefix'] == '10.0.0.1/32'
        assert rule['redirect'] == '203.0.113.1'
        assert rule['community'] == '65000:666'


def run_unit_tests():
    pytest.main([__file__, '-v', '--tb=short'])


if __name__ == '__main__':
    run_unit_tests()
