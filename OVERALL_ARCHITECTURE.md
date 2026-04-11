# Overall System Architecture

Comprehensive visual and textual representation of the DDoS Detection & Mitigation System.

## Mermaid Component Diagram

```mermaid
graph TD
    A[Traffic Source] --> B[Collector<br>pcap → flows]
    B --> C[Kafka raw_flows]
    C --> D[Detector<br>Ensemble ML/Threshold]
    D --> E[Kafka mitigation_alerts]
    E --> F[Mitigation<br>Rate Limit / Shield / Scrub]
    F --> G[Firewall / Cloud API]
    D --> H[Prometheus Metrics]
    F --> H
    B --> H
    H --> I[Grafana Dashboards]
    H --> J[Alertmanager<br>Slack/Email]
    K[API FastAPI] <--> L[Redis State]
    K <--> H
```

## Mermaid Data Flow Sequence

```mermaid
sequenceDiagram
    participant TS as Traffic Source
    participant Col as Collector
    participant Kafka
    participant Det as Detector
    participant Mit as Mitigation
    participant Mon as Monitoring

    TS->>Col: Packets
    Col->>Kafka: raw_flows
    Kafka->>Det: Consume
    Det->>Kafka: mitigation_alerts
    Det->>Mon: Metrics
    Kafka->>Mit: Consume
    Mit->>Mon: Action metrics
    Note over Det,Mit: <50ms E2E latency
```

## Deployment Stack

```mermaid
graph LR
    Docker[Docker Compose Local] --> K8s[K8s/Helm Prod]
    K8s --> TF[Terraform AWS<br>EKS+MSK+Redis]
    TF --> Ext[External Services<br>Shield/Cloud Armor]
```

## Key Technologies

| Layer | Tech |
|-------|------|
| Messaging | Kafka (TLS) |
| Cache/State | Redis (TLS) |
| Monitoring | Prometheus + Grafana + Alertmanager |
| ML | XGBoost + Isolation Forest |
| API | FastAPI |
| Deployment | Docker, Helm, Terraform |

Links: [ARCHITECTURE.md](ARCHITECTURE.md), [Folder Structure](FOLDER_STRUCTURE.txt)
