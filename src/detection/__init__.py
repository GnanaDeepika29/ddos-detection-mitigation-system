"""Detection Module — DDoS Attack Detection Engine"""

from .feature_extractor import FeatureExtractor, FlowFeatures, TrafficFeatures, FeatureConfig
from .threshold_detector import ThresholdDetector, ThresholdConfig, AttackType, ThresholdAlert
from .ml_detector import MLDetector, MLDetectorConfig, ModelType, DetectionResult
from .ensemble import EnsembleDetector, EnsembleConfig, VotingStrategy, EnsembleResult

__all__ = [
    # Feature extraction
    'FeatureExtractor',
    'FlowFeatures',
    'TrafficFeatures',
    'FeatureConfig',
    # Threshold detection
    'ThresholdDetector',
    'ThresholdConfig',
    'AttackType',
    'ThresholdAlert',
    # ML detection
    'MLDetector',
    'MLDetectorConfig',
    'ModelType',
    'DetectionResult',
    # Ensemble
    'EnsembleDetector',
    'EnsembleConfig',
    'VotingStrategy',
    'EnsembleResult',
]