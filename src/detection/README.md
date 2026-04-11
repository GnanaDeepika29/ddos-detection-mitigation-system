# Detection Service

The Detection Service is the core analysis engine of the DDoS mitigation system. It consumes network flows from the [Collector Service](../collector/README.md) and analyzes them to identify potential DDoS attacks. It uses a hybrid approach, combining rule-based thresholding and machine learning models to achieve high accuracy and low false positives.

## Components

The service consists of four main components:

*   `feature_extractor.py`: Extracts features from raw flow data.
*   `threshold_detector.py`: A rule-based detector that flags flows exceeding predefined thresholds.
*   `ml_detector.py`: A machine learning-based detector that uses trained models to classify flows.
*   `ensemble.py`: Combines the results from multiple detectors to make a final decision.

### `feature_extractor.py`

This module is responsible for transforming raw flow data into a set of numerical features that can be used by the detection models. It calculates a variety of statistical and time-series features that are indicative of different types of DDoS attacks.

**Key Features:**

*   **Comprehensive Feature Set**: Extracts a wide range of features, including packet rates, byte rates, protocol-specific ratios (e.g., SYN ratio), and inter-arrival time statistics.
*   **Window-based Aggregation**: Can aggregate features over time windows to capture temporal patterns.
*   **Normalization**: Normalizes features to a common scale, which is important for many machine learning models.

**Configuration:**

The feature extraction process is configured via a YAML file that specifies the features to be extracted and their parameters.

```yaml
# feature_config.yaml
features:
  - name: "packets_per_second"
  - name: "bytes_per_second"
  - name: "tcp_syn_ratio"
  - name: "interarrival_mean"
  - name: "interarrival_std"
```

### `threshold_detector.py`

This module implements a simple but effective rule-based detection method. It compares the features of a flow against a set of predefined thresholds. If a flow's features exceed these thresholds, it is flagged as suspicious.

**Key Features:**

*   **Dynamic Thresholds**: Thresholds can be loaded from a configuration file and updated dynamically.
*   **Multi-feature Rules**: Can define rules that combine multiple features (e.g., high packet rate AND high SYN ratio).
*   **Fast and Lightweight**: Provides a first line of defense that can quickly identify obvious attacks.

**Configuration:**

Thresholds are defined in a YAML file.

```yaml
# thresholds.yaml
- name: "High SYN Ratio"
  feature: "tcp_syn_ratio"
  threshold: 0.8
  operator: ">"

- name: "High Packet Rate"
  feature: "packets_per_second"
  threshold: 1000
  operator: ">"
```

### `ml_detector.py`

This module uses machine learning models to perform more sophisticated attack detection. It can load pre-trained models and use them to classify flows as benign or malicious.

**Key Features:**

*   **Multiple Model Support**: Can use various types of models, such as Isolation Forest, XGBoost, or deep learning models (e.g., LSTMs).
*   **Model Versioning**: Supports loading specific versions of models, allowing for A/B testing and rollback.
*   **High Accuracy**: Can detect complex and subtle attack patterns that may be missed by rule-based methods.

**Configuration:**

The ML detector is configured with the path to the trained model files.

```python
from .ml_detector import MLDetector

detector = MLDetector(model_path="models/isolation_forest_v1.pkl")
```

### `ensemble.py`

This module combines the outputs of the threshold detector and the ML detector to make a final, more robust decision. It uses a voting or weighting scheme to aggregate the results.

**Key Features:**

*   **Ensemble Strategies**: Supports different ensemble strategies, such as majority voting, weighted voting, and hierarchical decision-making.
*   **Reduced False Positives**: By combining multiple detection methods, the ensemble approach can reduce the rate of false positives.
*   **Configurable Logic**: The ensemble logic can be easily configured to suit different risk profiles.

**Configuration:**

The ensemble strategy is configured in a YAML file.

```yaml
# ensemble_config.yaml
strategy: "weighted_voting"
weights:
  threshold_detector: 0.3
  ml_detector: 0.7
```