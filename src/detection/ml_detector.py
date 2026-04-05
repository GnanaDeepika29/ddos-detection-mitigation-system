"""
Machine Learning Detector

Detects DDoS attacks using trained ML models including:
- Isolation Forest (unsupervised anomaly detection)
- One-Class SVM (unsupervised)
- LSTM Autoencoder (sequence-based detection)
- XGBoost Classifier (supervised)
"""

import numpy as np
import pickle
import json
from collections import deque
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List, Union, Protocol
from pathlib import Path
import time
import logging

from src.utils.paths import resolve_project_path

logger = logging.getLogger(__name__)


class TrafficFeaturesProtocol(Protocol):
    """Protocol for objects that can be converted to feature arrays"""
    def to_array(self) -> np.ndarray: ...


class ModelType(Enum):
    """Supported ML model types"""
    ISOLATION_FOREST = "isolation_forest"
    ONE_CLASS_SVM = "one_class_svm"
    LSTM_AUTOENCODER = "lstm_autoencoder"
    XGBOOST = "xgboost"
    ENSEMBLE = "ensemble"


@dataclass
class MLDetectorConfig:
    """Configuration for ML detector"""
    model_path: str = "models/isolation_forest.pkl"
    model_type: ModelType = ModelType.ISOLATION_FOREST

    # Detection thresholds
    anomaly_threshold: float = 0.5   # Score above this = anomaly
    confidence_threshold: float = 0.7

    # Performance settings
    batch_size: int = 32
    use_gpu: bool = False

    # Feature configuration
    feature_count: int = 23
    sequence_length: int = 10  # For LSTM models

    # Online learning
    enable_online_learning: bool = False
    update_interval_seconds: int = 3600  # Retrain every hour


@dataclass
class DetectionResult:
    """Result from ML detection"""
    is_attack: bool
    attack_type: Optional[str]
    confidence: float
    anomaly_score: float
    detection_time: float
    model_used: str
    features_used: List[str]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'is_attack': self.is_attack,
            'attack_type': self.attack_type,
            'confidence': self.confidence,
            'anomaly_score': self.anomaly_score,
            'detection_time': self.detection_time,
            'model_used': self.model_used,
            'features_used': self.features_used[:10],
            'detector': 'ml',
        }


class MLDetector:
    """
    Machine learning-based DDoS detector.
    Supports multiple model types with a unified interface.
    """

    def __init__(self, config: Optional[MLDetectorConfig] = None):
        self.config = config or MLDetectorConfig()
        self.model = None
        self.model_loaded = False
        self.scaler = None
        self.last_update_time = time.time()
        self.detection_history: deque = deque(maxlen=1000)
        self.stats = {
            'detections': 0,
            'attacks_detected': 0,
            'false_positives': 0,
            'average_inference_time_ms': 0.0,
            'inference_times': deque(maxlen=100),
        }
        self._load_model()
        logger.info(f"MLDetector initialized with model type: {self.config.model_type.value}")

    def _load_model(self):
        """Load ML model from disk"""
        model_path = resolve_project_path(self.config.model_path)

        if not model_path.exists():
            logger.warning(f"Model file not found: {self.config.model_path}")
            logger.info("Will operate in warmup mode until model is trained")
            self.model_loaded = False
            return

        try:
            if self.config.model_type == ModelType.ISOLATION_FOREST:
                import joblib
                self.model = joblib.load(model_path)
                self.model_loaded = True
                logger.info(f"Loaded Isolation Forest model from {model_path}")

            elif self.config.model_type == ModelType.XGBOOST:
                import xgboost as xgb
                self.model = xgb.Booster()
                self.model.load_model(str(model_path))
                self.model_loaded = True
                logger.info(f"Loaded XGBoost model from {model_path}")

            elif self.config.model_type == ModelType.ONE_CLASS_SVM:
                import joblib
                self.model = joblib.load(model_path)
                self.model_loaded = True
                logger.info(f"Loaded One-Class SVM model from {model_path}")

            elif self.config.model_type == ModelType.LSTM_AUTOENCODER:
                try:
                    from tensorflow import keras
                    self.model = keras.models.load_model(model_path)
                    self.model_loaded = True
                    logger.info(f"Loaded LSTM Autoencoder model from {model_path}")
                except ImportError:
                    logger.warning("TensorFlow not installed, LSTM Autoencoder not available")
                    self.model_loaded = False
                except Exception as e:
                    logger.error(f"Failed to load LSTM model: {e}")
                    self.model_loaded = False

            else:
                logger.error(f"Unsupported model type: {self.config.model_type}")
                self.model_loaded = False

        except ImportError as e:
            logger.warning(f"Required library not installed: {e}")
            self.model_loaded = False
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            self.model_loaded = False

    def _preprocess_features(self, features: np.ndarray) -> np.ndarray:
        """Preprocess features for model inference."""
        if len(features.shape) == 1:
            features = features.reshape(1, -1)
        features = np.nan_to_num(features, nan=0.0, posinf=1e6, neginf=-1e6)
        features = np.clip(features, -1e6, 1e6)
        return features

    def _predict_isolation_forest(self, features: np.ndarray) -> Dict[str, Any]:
        """Predict using Isolation Forest"""
        predictions = self.model.predict(features)

        if hasattr(self.model, 'score_samples'):
            # score_samples() returns negative anomaly scores (more negative = more anomalous)
            raw = -self.model.score_samples(features)
            scores = np.clip(raw, 0, None)
        else:
            scores = np.where(predictions == -1, 1.0, 0.0)

        is_anomaly = bool(predictions[0] == -1) if len(predictions) > 0 else False
        raw_score = float(scores[0]) if len(scores) > 0 else 0.0
        # Compress arbitrary positive anomaly magnitudes into a stable [0, 1)
        # range without flattening moderate anomalies to near-zero confidence.
        anomaly_score = raw_score / (1.0 + raw_score) if raw_score > 0 else 0.0

        confidence = anomaly_score if is_anomaly else 1.0 - anomaly_score
        confidence = float(min(0.95, max(0.05, confidence)))

        return {
            'is_attack': is_anomaly,
            'anomaly_score': anomaly_score,
            'confidence': confidence,
        }

    def _predict_xgboost(self, features: np.ndarray) -> Dict[str, Any]:
        """Predict using XGBoost classifier"""
        import xgboost as xgb

        dmatrix = xgb.DMatrix(features)
        predictions = self.model.predict(dmatrix)

        if len(predictions.shape) > 1:
            attack_prob = float(predictions[0][1]) if predictions.shape[1] > 1 else float(predictions[0])
        else:
            attack_prob = float(predictions[0])

        is_attack = attack_prob > self.config.anomaly_threshold

        return {
            'is_attack': is_attack,
            'anomaly_score': attack_prob,
            'confidence': attack_prob if is_attack else 1.0 - attack_prob,
        }

    def _predict_one_class_svm(self, features: np.ndarray) -> Dict[str, Any]:
        """Predict using One-Class SVM"""
        predictions = self.model.predict(features)
        
        if hasattr(self.model, 'decision_function'):
            decision_scores = self.model.decision_function(features)
            # Normalize decision scores to [0, 1] range
            anomaly_score = 1.0 / (1.0 + np.exp(decision_scores[0])) if len(decision_scores) > 0 else 0.5
        else:
            anomaly_score = 0.5

        is_anomaly = bool(predictions[0] == -1) if len(predictions) > 0 else False

        confidence = anomaly_score if is_anomaly else 1.0 - anomaly_score
        confidence = float(min(0.95, max(0.05, confidence)))

        return {
            'is_attack': is_anomaly,
            'anomaly_score': float(anomaly_score),
            'confidence': confidence,
        }

    def _predict_lstm_autoencoder(self, features: np.ndarray) -> Dict[str, Any]:
        """Predict using LSTM Autoencoder"""
        from tensorflow import keras
        
        n_features = features.shape[-1]
        # Create sequence
        seq = np.zeros((1, self.config.sequence_length, n_features), dtype=features.dtype)
        seq[0, -1, :] = features[0]

        reconstructed = self.model.predict(seq, verbose=0)
        mse = float(np.mean(np.square(seq - reconstructed)))

        # Normalize MSE to [0, 1] range (assuming max reasonable MSE is 1.0)
        anomaly_score = min(1.0, mse / 0.5)
        is_attack = anomaly_score > self.config.anomaly_threshold
        confidence = anomaly_score if is_attack else 1.0 - anomaly_score
        confidence = min(0.95, max(0.05, confidence))

        return {
            'is_attack': is_attack,
            'anomaly_score': anomaly_score,
            'confidence': confidence,
        }

    def detect(self, features: Union[TrafficFeaturesProtocol, np.ndarray]) -> Optional[DetectionResult]:
        """
        Detect DDoS attack using the loaded ML model.

        Args:
            features: Object with .to_array() method or a raw numpy array

        Returns:
            DetectionResult, or None if the model is not loaded.
        """
        if not self.model_loaded:
            logger.debug("Model not loaded, skipping ML detection")
            return None

        start_time = time.time()

        try:
            # Extract feature array
            if isinstance(features, np.ndarray):
                feature_array = features
            else:
                feature_array = features.to_array()

            processed_features = self._preprocess_features(feature_array)

            # Route to appropriate predictor
            if self.config.model_type == ModelType.ISOLATION_FOREST:
                result = self._predict_isolation_forest(processed_features)
            elif self.config.model_type == ModelType.XGBOOST:
                result = self._predict_xgboost(processed_features)
            elif self.config.model_type == ModelType.ONE_CLASS_SVM:
                result = self._predict_one_class_svm(processed_features)
            elif self.config.model_type == ModelType.LSTM_AUTOENCODER:
                result = self._predict_lstm_autoencoder(processed_features)
            else:
                logger.error(f"Unsupported model type: {self.config.model_type}")
                return None

            # Update statistics
            inference_time = (time.time() - start_time) * 1000  # ms
            self.stats['inference_times'].append(inference_time)
            self.stats['average_inference_time_ms'] = float(np.mean(self.stats['inference_times']))
            self.stats['detections'] += 1

            if result['is_attack']:
                self.stats['attacks_detected'] += 1

            # Create detection result
            detection_result = DetectionResult(
                is_attack=result['is_attack'],
                attack_type="ddos_ml" if result['is_attack'] else None,
                confidence=result['confidence'],
                anomaly_score=result['anomaly_score'],
                detection_time=time.time(),
                model_used=self.config.model_type.value,
                features_used=[],
            )

            self.detection_history.append(detection_result.__dict__)

            # Check for online learning
            if self.config.enable_online_learning:
                self._check_online_learning()

            # Log detection
            if detection_result.is_attack and detection_result.confidence > self.config.confidence_threshold:
                logger.info(
                    f"ML detection: attack detected with "
                    f"confidence={detection_result.confidence:.2f}, "
                    f"anomaly_score={detection_result.anomaly_score:.3f}"
                )

            return detection_result

        except Exception as e:
            logger.error(f"Error in ML detection: {e}")
            return None

    def _check_online_learning(self):
        """Check if online learning should be triggered"""
        current_time = time.time()
        if current_time - self.last_update_time > self.config.update_interval_seconds:
            self.last_update_time = current_time
            logger.info("Online learning interval reached, would retrain model")

    def get_stats(self) -> Dict[str, Any]:
        """Get detector statistics"""
        return {
            'detections': self.stats['detections'],
            'attacks_detected': self.stats['attacks_detected'],
            'false_positives': self.stats['false_positives'],
            'average_inference_time_ms': self.stats['average_inference_time_ms'],
            'model_loaded': self.model_loaded,
            'model_type': self.config.model_type.value,
            'detection_history_size': len(self.detection_history),
            'config': {
                'anomaly_threshold': self.config.anomaly_threshold,
                'confidence_threshold': self.config.confidence_threshold,
                'batch_size': self.config.batch_size,
            },
        }

    def reload_model(self, model_path: Optional[str] = None):
        """Reload model from disk"""
        if model_path:
            self.config.model_path = model_path
        self._load_model()
