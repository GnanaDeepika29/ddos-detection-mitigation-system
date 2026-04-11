# Mitigation Service

Executes countermeasures upon attack detection alerts from Kafka `mitigation_alerts` topic.

## Components

* `engine.py`: Alert consumer and strategy dispatcher.
* `rate_limiter.py`: Distributed rate limiting with Redis (token bucket).
* `rule_injector.py`: Dynamic iptables/nftables rules for DROP/TARPIT.
* `cloud_shield.py`: API calls to AWS Shield, Cloudflare, etc.
* `scrubber_redirect.py`: BGP FlowSpec or GRE tunnel rerouting.

## Features

* Multi-strategy execution (parallel/serial).
* Rollback on false positive.
* Metrics for action effectiveness.

## Configuration

`config/thresholds.yaml` for action severity mappings.

```python
# Example flow
alert = consume_kafka()
if alert.severity > threshold:
    rate_limiter.block_ip(alert.src_ip, duration='5m')
    cloud_shield.activate_shield()
```

Logs all actions; integrates with Prometheus.
