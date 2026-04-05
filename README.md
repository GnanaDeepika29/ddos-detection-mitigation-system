# ☁️🛡️ CloudShield: Real-time DDoS Detection & Mitigation for Cloud Networks

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Kafka](https://img.shields.io/badge/Apache%20Kafka-Streaming-brightgreen)](https://kafka.apache.org/)
[![ML](https://img.shields.io/badge/ML-Isolation%20Forest-orange)]()

CloudShield is a **real-time, ML-enhanced DDoS detection and automated mitigation system** designed for cloud-native environments (AWS, GCP, Azure). It ingests network flow data, detects anomalies using hybrid threshold/ML models, and triggers automated mitigation actions via cloud provider APIs or local rule engines.

> ⚠️ **For defensive/educational use only.** Authorized deployment only on networks you own or have explicit permission to monitor. Unauthorized interception or testing is illegal.

---

## 🎯 Features

- **Real-time ingestion** – Packet mirroring, VPC Flow Logs, sFlow, or eBPF
- **Hybrid detection engine** – Statistical thresholds + ML (Isolation Forest / Autoencoder)
- **Multi-cloud mitigation** – AWS Shield Advanced, Azure DDoS Protection, GCP Armor, or custom iptables/eBPF
- **Low latency** – Sub-second detection via sliding windows + Kafka streaming
- **Observability** – Prometheus metrics + Grafana dashboards
- **Modular & extensible** – Add your own detectors or mitigation actions

---

## 🏗️ Architecture Overview
[Traffic Sources] → [Collector] → [Kafka] → [Detector (ML + Threshold)]
↓
[Prometheus/Grafana] ← [Mitigation Engine] ← [Alert if Anomaly]
↓
[Cloud Shield APIs / iptables / BGP]

text

---

## 📁 Project Structure (Abridged)

See the full folder structure in the repository. Key modules:

- `src/collector/` – Traffic capture & flow builder  
- `src/streaming/` – Kafka producers/consumers  
- `src/detection/` – Feature extraction & ML models  
- `src/mitigation/` – Automated response actions  
- `deployment/` – Kubernetes, Terraform, Ansible scripts  

---

## 🚀 Quick Start (Local Dev Environment)

### Prerequisites

- Python 3.9+
- Docker & Docker Compose
- Apache Kafka (or use the provided `docker-compose.yml`)
- Optional: AWS/Azure/GCP CLI for cloud mitigation

### 1. Clone & Setup

```bash
git clone https://github.com/your-org/cloudshield.git
cd cloudshield
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows
pip install -r requirements.txt
2. Environment Configuration
bash
cp .env.example .env
# Edit .env – add cloud credentials, Kafka brokers, thresholds
3. Start Dependencies (Kafka + Prometheus + Grafana)
bash
docker-compose up -d
Optional profiles:
- `docker compose --profile alerts up -d` to include Alertmanager
- `docker compose --profile logging up -d` to include Elasticsearch, Logstash, and Kibana
4. Run the Detection Pipeline
Terminal 1 – Collector & Producer:

bash
python src/collector/packet_capture.py --interface eth0 | python src/streaming/producer.py
Terminal 2 – Consumer + Detector:

bash
python src/streaming/consumer.py --detection-model ensemble
Terminal 3 – Mitigation Engine:

bash
python src/mitigation/cloud_shield.py --mode auto
5. View Metrics
Grafana: http://localhost:3000 (admin/admin)

Prometheus: http://localhost:9090

🧪 Testing with Simulated Attacks (Isolated Lab Only)
Do not run against live production or third-party networks.

Generate benign + attack traffic using included script:

bash
python scripts/simulate_traffic.py --target 192.168.1.100 --attack syn_flood --rate 10000 --duration 30
Detection output example:

text
[ALERT] 2025-03-29T10:32:15Z | src_ip=203.0.113.5 | attack=SYN_FLOOD | confidence=0.94 | actions=[rate_limit, cloud_shield]
☁️ Cloud Deployment (Production)
AWS
bash
cd deployment/terraform/aws
terraform init && terraform apply
# Deploys VPC, Flow Logs, EKS, MSK (Kafka), and IAM roles
Then apply Kubernetes manifests:

bash
kubectl apply -f deployment/kubernetes/
Azure / GCP
See deployment/terraform/azure/ and deployment/terraform/gcp/ for similar setups.

🤖 Training Custom ML Models
We provide a baseline Isolation Forest model. To train on your own traffic:

bash
python scripts/train_model.py --data data/processed/normal_flows.parquet --output models/custom_model.pkl
Supported models: Isolation Forest, LSTM-Autoencoder, One-Class SVM.

📊 Dashboards
Grafana dashboard includes:

Incoming packets/sec & bits/sec (top talkers)

Entropy over destination IPs

Detection alerts per minute

Mitigation actions taken

Import from src/monitoring/grafana_dashboard.json.

⚙️ Configuration
Main config file: config/prod.yaml

yaml
detection:
  window_seconds: 5
  threshold_packets_per_sec: 10000
  entropy_threshold: 0.8
  ml_model_path: "models/isolation_forest.pkl"

mitigation:
  auto_mitigate: true
  actions:
    - rate_limit
    - cloud_shield
  rate_limit_pps: 500

kafka:
  bootstrap_servers: "kafka:9092"
  topic: "network_flows"

cloud_provider: "aws"   # aws, azure, gcp, none
🧰 Requirements
See requirements.txt. Core libraries:

scapy – Packet capture

kafka-python – Streaming

scikit-learn – ML detection

prometheus_client – Metrics

boto3 / azure-mgmt-network / google-cloud-compute – Cloud APIs

fastapi + uvicorn (optional REST API)

🛡️ Responsible Use & Limitations
Not a replacement for professional DDoS protection (Cloudflare, AWS Shield Advanced, etc.) – use as an additional layer.

False positives possible – tune thresholds on your own baseline traffic.

Does not protect against all DDoS vectors (e.g., application-layer attacks need WAF).

Legal compliance required – monitor only authorized networks and follow data retention laws (GDPR, etc.).

🤝 Contributing
We welcome defensive contributions! Please:

Open an issue describing your proposed detector or mitigation module.

Ensure all tests pass (pytest tests/).

Do not submit code that could be weaponized (e.g., attack generation).

📚 References
CIC-DDoS2019 Dataset

AWS Best Practices for DDoS Resiliency

Scapy Documentation

📄 License
MIT License – see LICENSE file.
This license applies to the defensive codebase only. Misuse for actual attacks is not authorized.

📬 Contact
For defensive research collaboration: security@yourdomain.com
Do not send live attack data or ask for help attacking networks.

text

---

### Key sections explained:

- **Architecture diagram** – gives high-level flow for newcomers.
- **Quick start** – gets a local dev environment running in minutes.
- **Testing** – explicitly warns to use isolated labs only.
- **Cloud deployment** – uses Terraform + K8s for production readiness.
- **Configuration** – shows how to tune thresholds and choose ML models.
- **Responsible use** – legal and ethical disclaimer.
- **References** – points to legitimate datasets and cloud best practices.

You can adapt the GitHub URL, contact email, and cloud-specific details to your actual project. This README is **safe for public repositories** as it does not contain exploit code or encourage malicious activity.
