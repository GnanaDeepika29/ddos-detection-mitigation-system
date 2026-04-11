# Streaming Service

Shared Kafka producers/consumers for inter-service communication (secure TLS/SASL).

## Components

* `producer.py`: Flow/alert publishing.
* `consumer.py`: Reliable consumption with offset commits.
* `secure_client.py`: TLS-secured Kafka clients.
* `window_aggregator.py`: Time-based aggregation (e.g., 1min windows for features).

## Topics

* `raw_flows`: From collector.
* `mitigation_alerts`: From detector.
* `mitigation_actions`: From mitigator.

## Features

* Exactly-once semantics.
* Dead letter queue for failed messages.
* Schema registry compatible.

## Usage

```python
from src.streaming.producer import FlowProducer
producer = FlowProducer(topic='raw_flows')
producer.send(flow_data)
```

Config via `utils/env_loader.py` for brokers, certs.
