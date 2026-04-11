# Collector Service

Captures network traffic and converts to standardized flow records for streaming analysis.

## Components

* `packet_capture.py`: Packet sniffing using pcap/scapy.
* `flow_builder.py`: Aggregates packets into 5-tuple flows (src/dst IP/port, protocol).
* `traffic_collector.py`: Main orchestrator, publishes to Kafka.
* `cloud_agent.py`: Cloud-specific collectors (e.g., VPC Flow Logs).

## Features

* Real-time capture at line-rate.
* Synthetic traffic generation for testing.
* Output: Flow JSON to `raw_flows` Kafka topic.

## Usage

```bash
# Local
scripts/run_collector.py --interface eth0 --kafka raw_flows

# Cloud
src/collector/cloud_agent.py --provider aws
```

Config via `config/dev.yaml` for interfaces, batch size, sampling rate.
