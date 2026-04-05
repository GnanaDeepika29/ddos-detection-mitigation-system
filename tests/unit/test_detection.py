"""
Unit Tests for Detection Module

Tests for feature extraction, threshold detection, ML detection, and ensemble methods.
"""

import pytest
import time
import json
import numpy as np
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime
from pathlib import Path

from src.detection.feature_extractor import (
    FeatureExtractor, FlowFeatures, TrafficFeatures, FeatureConfig
)
from src.streaming.window_aggregator import TimeWindow
from src.detection.threshold_detector import (
    ThresholdDetector, ThresholdConfig, AttackType, ThresholdAlert
)
from src.detection.ml_detector import (
    MLDetector, MLDetectorConfig, ModelType, DetectionResult
)
from src.detection.ensemble import (
    EnsembleDetector, EnsembleConfig, VotingStrategy, EnsembleResult
)


class TestFeatureExtractor:

    def setup_method(self):
        self.config = FeatureConfig(
            max_flows_per_window=1000,
            enable_tcp_flags=True,
            window_sizes=[1, 5, 10],
        )
        self.extractor = FeatureExtractor(self.config)

    def test_extract_flow_features_tcp(self):
        flow_dict = {
            'flow_id': 'test_flow_001',
            'ip_src': '192.168.1.100',
            'ip_dst': '10.0.0.1',
            'protocol': 6,
            'sport': 54321,
            'dport': 80,
            'total_packets': 150,
            'total_bytes': 15000,
            'packets_per_sec': 50.0,
            'bytes_per_sec': 5000.0,
            'duration': 3.0,
            'tcp_syn_count': 1,
            'tcp_syn_ack_count': 1,
            'tcp_rst_count': 0,
            'tcp_fin_count': 1,
            'tcp_window_avg': 65535,
            'application_protocol': 'HTTP',
        }

        features = self.extractor.extract_flow_features(flow_dict)

        assert features.flow_id == 'test_flow_001'
        assert features.src_ip == '192.168.1.100'
        assert features.protocol == 6
        assert features.total_packets == 150
        assert features.tcp_syn_ratio == 1.0
        assert features.app_protocol == 'HTTP'

        feature_array = features.to_array()
        assert isinstance(feature_array, np.ndarray)
        assert len(feature_array) == 11

    def test_extract_flow_features_udp(self):
        flow_dict = {
            'flow_id': 'test_flow_002',
            'ip_src': '192.168.1.200',
            'ip_dst': '10.0.0.2',
            'protocol': 17,
            'sport': 53,
            'dport': 12345,
            'total_packets': 50,
            'total_bytes': 5000,
            'duration': 1.0,
            'udp_payload_avg': 100.0,
        }

        features = self.extractor.extract_flow_features(flow_dict)

        assert features.protocol == 17
        assert features.udp_payload_avg == 100.0

    def test_extract_traffic_features(self):
        window_data = {
            'window_start': time.time(),
            'duration': 5.0,
            'total_packets': 50000,
            'total_bytes': 50000000,
            'flows': [{'id': 1}, {'id': 2}],
            'unique_src_ips': 1000,
            'unique_dst_ips': 50,
            'entropy_src_ip': 3.2,
            'entropy_dst_ip': 1.5,
            'protocol_counts': {6: 800, 17: 150, 1: 50},
            'src_ip_counts': {'192.168.1.1': 1000, '192.168.1.2': 500},
            'dst_ip_counts': {'10.0.0.1': 800, '10.0.0.2': 200},
            'packet_size_distribution': [64, 128, 256, 512, 1024, 1500],
            'tcp_flag_counts': {'syn': 100, 'rst': 5, 'fin': 10},
        }

        features = self.extractor.extract_traffic_features(window_data, 5)

        assert features.total_packets == 50000
        assert features.packets_per_second == 10000.0
        assert features.unique_src_ips == 1000
        assert features.entropy_src_ip == 3.2
        assert features.tcp_ratio == 0.8
        assert features.udp_ratio == 0.15
        assert features.icmp_ratio == 0.05
        assert isinstance(features.is_syn_flood_suspicious, bool)
        assert isinstance(features.is_udp_flood_suspicious, bool)

    def test_extract_traffic_features_accepts_window_aggregator_schema(self):
        window = TimeWindow(start_time=time.time(), end_time=time.time() + 5)
        window.add_flow({
            'flow_id': 'flow_1',
            'ip_src': '192.168.1.10',
            'ip_dst': '10.0.0.1',
            'protocol': 6,
            'sport': 12345,
            'dport': 80,
            'total_packets': 100,
            'total_bytes': 10000,
            'avg_packet_size': 100,
            'tcp_syn_count': 95,
            'tcp_rst_count': 1,
            'tcp_fin_count': 0,
        })

        features = self.extractor.extract_traffic_features(window.to_dict(), 5)

        assert features.total_flows == 1
        assert features.tcp_ratio == 1.0
        assert features.syn_ratio == 0.95
        assert features.top_src_ips[0][0] == '192.168.1.10'

    def test_entropy_calculation(self):
        counter = {'a': 10, 'b': 20, 'c': 30}
        entropy = self.extractor._calculate_entropy(counter)
        assert 1.45 < entropy < 1.47

    def test_syn_flood_detection(self):
        features = TrafficFeatures(timestamp=time.time(), window_size=5)
        features.tcp_ratio = 0.9
        features.syn_ratio = 0.85
        features.unique_src_ips = 500
        features.packets_per_second = 20000

        assert self.extractor._detect_syn_flood(features) is True

    def test_udp_flood_detection(self):
        features = TrafficFeatures(timestamp=time.time(), window_size=5)
        features.udp_ratio = 0.85
        features.packets_per_second = 20000

        assert self.extractor._detect_udp_flood(features) is True


class TestThresholdDetector:

    def setup_method(self):
        self.config = ThresholdConfig(
            packets_per_second_threshold=10000,
            syn_flood_syn_ratio=0.8,
            syn_flood_min_rate=5000,
            enable_dynamic_thresholds=False,
            alert_cooldown_seconds=1,
        )
        self.detector = ThresholdDetector(self.config)

    def test_volumetric_detection_high_pps(self):
        features = TrafficFeatures(timestamp=time.time(), window_size=5)
        features.packets_per_second = 50000
        features.top_src_ips = [('192.168.1.1', 10000)]

        alert = self.detector.detect_volumetric(features, time.time())

        assert alert is not None
        assert alert.attack_type == AttackType.PPS_FLOOD
        assert alert.severity == 'high'
        assert alert.confidence > 0.8

    def test_volumetric_detection_critical(self):
        features = TrafficFeatures(timestamp=time.time(), window_size=5)
        features.packets_per_second = 60001
        features.top_src_ips = [('192.168.1.1', 60001)]

        alert = self.detector.detect_volumetric(features, time.time())

        assert alert is not None
        assert alert.severity == 'critical'

    def test_volumetric_detection_below_threshold(self):
        features = TrafficFeatures(timestamp=time.time(), window_size=5)
        features.packets_per_second = 5000

        assert self.detector.detect_volumetric(features, time.time()) is None

    def test_syn_flood_detection(self):
        features = TrafficFeatures(timestamp=time.time(), window_size=5)
        features.syn_ratio = 0.9
        features.packets_per_second = 10000
        features.top_dst_ips = [('10.0.0.1', 5000)]

        alert = self.detector.detect_syn_flood(features, time.time())

        assert alert is not None
        assert alert.attack_type == AttackType.SYN_FLOOD
        assert alert.confidence > 0.8

    def test_udp_flood_detection(self):
        features = TrafficFeatures(timestamp=time.time(), window_size=5)
        features.udp_ratio = 0.9
        features.packets_per_second = 15000

        alert = self.detector.detect_udp_flood(features, time.time())

        assert alert is not None
        assert alert.attack_type == AttackType.UDP_FLOOD

    def test_entropy_anomaly_detection(self):
        features = TrafficFeatures(timestamp=time.time(), window_size=5)
        features.entropy_src_ip = 0.3

        for _ in range(9):
            self.detector.history_entropy.append(0.8)

        alert = self.detector.detect_entropy_anomaly(features, time.time())

        assert alert is not None
        assert alert.attack_type == AttackType.DISTRIBUTED_ENTROPY

    def test_cooldown_mechanism(self):
        features = TrafficFeatures(timestamp=time.time(), window_size=5)
        features.packets_per_second = 50000

        alert1 = self.detector.detect_volumetric(features, time.time())
        assert alert1 is not None

        # Second call within cooldown should be suppressed
        alert2 = self.detector.detect_volumetric(features, time.time())
        assert alert2 is None


class TestMLDetector:

    def setup_method(self):
        self.config = MLDetectorConfig(
            model_path="models/isolation_forest.pkl",
            model_type=ModelType.ISOLATION_FOREST,
            anomaly_threshold=0.5,
            confidence_threshold=0.7,
        )

        self.mock_model = Mock()
        self.mock_model.predict.return_value = np.array([-1])  # anomaly
        self.mock_model.score_samples.return_value = np.array([-0.5])

        self.detector = MLDetector(self.config)
        self.detector.model_loaded = True
        self.detector.model = self.mock_model

    def test_ml_detection_anomaly(self):
        features = TrafficFeatures(timestamp=time.time(), window_size=5)
        features.total_packets = 100000
        features.packets_per_second = 20000

        result = self.detector.detect(features)

        assert result is not None
        assert result.is_attack is True
        assert result.anomaly_score > 0
        assert result.confidence > 0.1
        assert result.model_used == 'isolation_forest'

    def test_ml_detection_normal(self):
        self.mock_model.predict.return_value = np.array([1])  # normal

        features = TrafficFeatures(timestamp=time.time(), window_size=5)
        features.total_packets = 1000

        result = self.detector.detect(features)

        assert result is not None
        assert result.is_attack is False

    def test_model_loading(self):
        with patch('pathlib.Path.exists', return_value=True):
            with patch('joblib.load', return_value=self.mock_model):
                config = MLDetectorConfig(
                    model_path="models/isolation_forest.pkl",
                    model_type=ModelType.ISOLATION_FOREST,
                )
                detector = MLDetector(config)

        assert detector.model_loaded is True

    def test_default_model_path_resolves_from_project_root(self):
        detector = MLDetector(MLDetectorConfig())

        expected = Path(__file__).resolve().parents[2] / "models" / "isolation_forest.pkl"
        resolved = detector.config.model_path

        assert resolved == "models/isolation_forest.pkl"
        assert expected.exists()


class TestEnsembleDetector:

    def setup_method(self):
        self.config = EnsembleConfig(
            voting_strategy=VotingStrategy.WEIGHTED,
            threshold_weight=0.4,
            ml_weight=0.4,
            entropy_weight=0.2,
            min_confidence=0.6,
            min_agreeing_detectors=2,
            cooldown_seconds=0,
        )

        self.mock_threshold = Mock()
        self.mock_ml = Mock()

        self.ensemble = EnsembleDetector(
            config=self.config,
            threshold_detector=self.mock_threshold,
            ml_detector=self.mock_ml,
        )

    def test_weighted_voting(self):
        features = TrafficFeatures(timestamp=time.time(), window_size=5)
        features.entropy_src_ip = 4.0  # High entropy, no vote

        mock_alert = Mock()
        mock_alert.attack_type = AttackType.SYN_FLOOD
        mock_alert.confidence = 0.9
        mock_alert.severity = "high"
        mock_alert.affected_ips = []
        self.mock_threshold.detect.return_value = [mock_alert]

        mock_ml_result = Mock()
        mock_ml_result.is_attack = True
        mock_ml_result.confidence = 0.85
        mock_ml_result.attack_type = "ddos_ml"
        self.mock_ml.detect.return_value = mock_ml_result

        result = self.ensemble.detect(features)

        assert result is not None
        assert result.is_attack is True
        assert result.confidence > 0.7
        assert result.attack_type == "syn_flood"


def run_unit_tests():
    pytest.main([__file__, '-v', '--tb=short'])


if __name__ == '__main__':
    run_unit_tests()
