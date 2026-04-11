# System Architecture

This document provides a high-level overview of the DDoS Detection and Mitigation System's architecture. The system is designed as a modular, cloud-native platform for real-time traffic analysis and threat response.

## 1. High-Level Overview

The system follows a microservices-based architecture, where each core component is a separate, containerized service. This design allows for independent scaling, development, and deployment of each part of the system.

The primary data flow is as follows:
1.  **Traffic Collection**: Network traffic is captured and converted into a standardized flow format.
2.  **Streaming & Processing**: Flow data is published to a Kafka message bus for real-time, distributed processing.
3.  **Detection**: A detection engine consumes the flow data, analyzing it for patterns indicative of a DDoS attack using a hybrid of rule-based and machine learning models.
4.  **Mitigation**: If an attack is detected, the mitigation engine is triggered to apply countermeasures, such as blocking IPs, rate-limiting traffic, or redirecting traffic to a scrubbing center.
5.  **Monitoring & Alerting**: The entire system is monitored, with metrics and logs collected for real-time visibility and alerting.

## 2. Core Microservices

The system is composed of four main microservices:

### a. Collector (`collector`)

*   **Responsibility**: Captures raw network packets and aggregates them into traffic flows.
*   **Implementation**: Uses `pcap` (via `scapy` or `pcapy`) for packet capture. It can also generate synthetic traffic for testing purposes.
*   **Output**: Publishes flow data (e.g., source/destination IPs, ports, protocol, packet counts, byte counts) to the `raw_flows` Kafka topic.

### b. Detector (`detector`)

*   **Responsibility**: Analyzes traffic flows to detect DDoS attacks.
*   **Implementation**: Consumes data from Kafka. It uses a hybrid detection strategy:
    *   **Threshold-based Detector**: Simple rules based on packet-per-second (PPS) or bits-per-second (BPS) thresholds.
    *   **Machine Learning Detector**: Utilizes pre-trained models (e.g., Isolation Forest, XGBoost) to identify more complex attack patterns.
    *   **Ensemble Logic**: Combines the outputs of multiple detectors to make a final decision, reducing false positives.
*   **Output**: If an attack is detected, it publishes a mitigation alert to the `mitigation_alerts` Kafka topic and sends metrics to Prometheus/InfluxDB.

### c. Mitigation (`mitigation`)

*   **Responsibility**: Takes action to block or control malicious traffic based on alerts from the detector.
*   **Implementation**: Consumes alerts from the `mitigation_alerts` topic. It supports multiple mitigation strategies:
    *   **Rate Limiter**: Implements distributed rate-limiting using Redis.
    *   **Firewall Rule Injector**: Dynamically adds rules to a local firewall (`iptables`, `nftables`) to `DROP` or `TARPIT` malicious traffic.
    *   **Cloud Shield**: Integrates with cloud provider DDoS services (AWS Shield, Azure DDoS Protection, GCP Cloud Armor, Cloudflare).
    *   **Scrubber Redirect**: Reroutes traffic to a scrubbing center via BGP FlowSpec or GRE tunnels.
*   **Output**: Logs actions taken and sends metrics on mitigation activities.

### d. API (`api`)

*   **Responsibility**: Provides a RESTful API for interacting with the system.
*   **Implementation**: A FastAPI application that allows users to:
    *   View system status and statistics.
    *   Manually trigger or override mitigation actions.
    *   Configure detection thresholds and rules.
*   **Interaction**: Communicates with other services via Redis and direct inspection where necessary.

## 3. Data Flow & Supporting Services

The microservices are supported by a set of robust, open-source infrastructure components, all managed via Docker Compose for local deployment.

+-----------------+ +-----------------+ +-----------------+ +-----------------+ | Traffic Source |----->| Collector |----->| Kafka |----->| Detector | | (Internet/Sim) | +-----------------+ | (raw_flows topic) | +-----------------+ +-----------------+ +-----------------+ | | (Attack Detected) v +-----------------+ +-----------------+ | Kafka |----->| Mitigation | |(mitigation_alerts| +-----------------+ | topic) | | +-----------------+ | (Apply Rules) v +--------------------+ | Firewall/Cloud API | +--------------------+


plainText

### Supporting Infrastructure:

*   **Kafka**: The central message bus for asynchronous, real-time data streaming between services.
*   **Redis**: Used for distributed state management, caching, and implementing distributed locks and rate-limiting.
*   **Prometheus**: Collects time-series metrics from all services for monitoring and alerting.
*   **Grafana**: Visualizes metrics from Prometheus and other data sources in real-time dashboards.
*   **InfluxDB**: A time-series database used by the detector for storing baseline traffic statistics.
*   **Elasticsearch, Logstash, Kibana (ELK Stack)**: Provides a centralized logging solution for collecting, parsing, and analyzing logs from all services.

## 4. Deployment

The system is designed for cloud-native deployment. The repository includes configurations for:
*   **Docker Compose**: For local development and testing.
*   **Kubernetes/Helm**: For scalable production deployment in a Kubernetes cluster.
*   **Terraform**: For provisioning the necessary cloud infrastructure.

This architecture ensures the system is scalable, resilient, and maintainable, providing a solid foundation for a production-grade DDoS protection platform.