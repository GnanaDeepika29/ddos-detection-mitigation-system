"""
CloudShield DDoS Detection and Mitigation System
"""

__version__ = "1.0.0"
__author__ = "CloudShield Team"
__license__ = "MIT"

# Import key modules for easy access
from src.detection.threshold_detector import ThresholdDetector, ThresholdConfig
from src.detection.ml_detector import MLDetector, MLDetectorConfig
from src.detection.ensemble import EnsembleDetector, EnsembleConfig

__all__ = [
    "__version__",
    "ThresholdDetector",
    "ThresholdConfig", 
    "MLDetector",
    "MLDetectorConfig",
    "EnsembleDetector",
    "EnsembleConfig",
]