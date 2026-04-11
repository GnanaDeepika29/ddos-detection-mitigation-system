import asyncio
from pathlib import Path

from unittest.mock import patch

from tests.integration.test_streaming_pipeline import mock_kafka
from src.detection.ensemble import EnsembleDetector, EnsembleConfig
from src.detection.threshold_detector import ThresholdDetector, ThresholdConfig
from src.mitigation.cloud_shield import CloudProvider, CloudShieldConfig
from src.utils.paths import resolve_project_path
from scripts.run_collector import CollectorService
from scripts.run_detector import DetectorService
from scripts.run_mitigation import MitigationService


def test_ensemble_detect_from_dict_smoke():
    detector = EnsembleDetector(
        config=EnsembleConfig(cooldown_seconds=0),
        threshold_detector=ThresholdDetector(
            ThresholdConfig(
                packets_per_second_threshold=1000,
                enable_dynamic_thresholds=False,
            )
        ),
    )

    result = detector.detect_from_dict({
        "window_size_seconds": 5,
        "metrics": {
            "window_start": 1.0,
            "duration": 5.0,
            "total_packets": 50000,
            "total_bytes": 1000000,
            "flows": [{"id": 1}],
            "unique_src_ips": 1000,
            "unique_dst_ips": 5,
            "entropy_src_ip": 0.2,
            "entropy_dst_ip": 1.0,
            "protocol_counts": {6: 1000},
            "src_ip_counts": {"192.168.1.1": 1000},
            "dst_ip_counts": {"10.0.0.1": 1000},
            "packet_size_distribution": [64, 128, 256],
            "tcp_flag_counts": {"syn": 950, "rst": 1, "fin": 0},
        },
    })

    assert result is not None
    assert result.is_attack is True


def test_detector_service_accepts_model_path_env(monkeypatch):
    monkeypatch.setenv("MODEL_PATH", "models/isolation_forest.pkl")
    monkeypatch.delenv("ML_MODEL_PATH_ISOLATION_FOREST", raising=False)

    service = DetectorService()

    assert str(service.ml_detector.config.model_path) == str(Path("models/isolation_forest.pkl").resolve())

    with patch("scripts.run_detector.AlertSeverity") as mock_severity, \
         patch.object(service.alert_producer, "flush", lambda: None), \
         patch.object(service.alert_producer, "stop", lambda: None):
        mock_severity.MEDIUM = "medium"
        service.stop()


def test_mitigation_service_cloud_provider_env(monkeypatch):
    monkeypatch.setenv("CLOUD_PROVIDER", "none")

    service = MitigationService()

    assert service.cloud_shield.config.provider == CloudProvider.NONE
    service.stop()


def test_resolve_project_path_rebases_missing_app_prefix():
    resolved = resolve_project_path("/app/models/isolation_forest.pkl")
    assert resolved == (Path(__file__).resolve().parents[2] / "models" / "isolation_forest.pkl")


def test_collector_service_synthetic_mode_emits_flows():
    async def run_test():
        mock_kafka.reset()
        with patch("scripts.run_collector.FlowProducer.start", lambda self: setattr(self, "is_running", True)), \
             patch("scripts.run_collector.FlowProducer.stop", lambda self: setattr(self, "is_running", False)), \
             patch("scripts.run_collector.FlowProducer.flush", lambda self: None), \
             patch(
                 "scripts.run_collector.FlowProducer.send_flow",
                 lambda self, flow, key=None: mock_kafka.produce("network_flows", key, flow) or True,
             ):
            service = CollectorService(synthetic=True)
            task = asyncio.create_task(service.run())
            await asyncio.sleep(0.05)
            service.stop()
            await task
            assert len(mock_kafka.topics.get("network_flows", [])) > 0

    asyncio.run(run_test())
