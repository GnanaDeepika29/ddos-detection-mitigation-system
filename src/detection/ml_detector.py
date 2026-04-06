"""
Machine Learning Detector

Detects DDoS attacks using trained ML models including:
- Isolation Forest (unsupervised anomaly detection)
- One-Class SVM (unsupervised)
- LSTM Autoencoder (sequence-based detection)
- XGBoost Classifier (supervised)
"""

import numpy as np
import logging
import time
from collections import deque
from enum import Enum
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Any, Optional, List, Union, Protocol

# FIX BUG-15: Use a relative import so the module works regardless of CWD or
# whether the consumer has added the repository root to sys.path.  An absolute
# 'from src.utils.paths import ...' fails when the package is imported from a
# different working directory or during unit tests.
try:
    from ..utils.paths import resolve_project_path  # type: ignore[import]
except ImportError:
    # Fallback: treat the path as a plain Path object without resolution.
    def resolve_project_path(p: str) -> Path:  # type: ignore[misc]
        return Path(p)

logger = logging.getLogger(__name__)


class TrafficFeaturesProtocol(Protocol):
    """Protocol for objects that expose a .to_array() method."""
    def to_array(self) -> np.ndarray: ...


class ModelType(Enum):
    ISOLATION_FOREST = "isolation_forest"
    ONE_CLASS_SVM = "one_class_svm"
    LSTM_AUTOENCODER = "lstm_autoencoder"
    XGBOOST = "xgboost"
    ENSEMBLE = "ensemble"


@dataclass
class MLDetectorConfig:
    model_path: str = "models/isolation_forest.pkl"
    model_type: ModelType = ModelType.ISOLATION_FOREST
    anomaly_threshold: float = 0.5
    confidence_threshold: float = 0.7
    batch_size: int = 32
    use_gpu: bool = False
    feature_count: int = 23
    sequence_length: int = 10          # For LSTM models
    enable_online_learning: bool = False
    update_interval_seconds: int = 3600


@dataclass
class DetectionResult:
    is_attack: bool
    attack_type: Optional[str]
    confidence: float
    anomaly_score: float
    detection_time: float
    model_used: str
    features_used: List[str]

    def to_dict(self) -> Dict[str, Any]:
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
    """ML-based DDoS detector supporting multiple model types."""

    def __init__(self, config: Optional[MLDetectorConfig] = None) -> None:
        self.config = config or MLDetectorConfig()
        self.model: Any = None
        self.model_loaded = False
        self.scaler: Any = None
        self.last_update_time = time.time()
        self.detection_history: deque = deque(maxlen=1_000)
        self.stats: Dict[str, Any] = {
            'detections': 0,
            'attacks_detected': 0,
            'false_positives': 0,
            'average_inference_time_ms': 0.0,
            'inference_times': deque(maxlen=100),
        }

        # FIX BUG-18: LSTM autoencoder requires a rolling feature-history
        # buffer so it can build a real sequence rather than a zero-padded one.
        self._lstm_buffer: deque = deque(maxlen=self.config.sequence_length)

        self._load_model()
        logger.info(f"MLDetector initialised: {self.config.model_type.value}")

    # ------------------------------------------------------------------
    # Model loading
    # ------------------------------------------------------------------

    def _resolve_path(self, path_str: str) -> Path:
        """
        Resolve model path.

        FIX BUG-21: If the caller passes an absolute path (e.g. via
        reload_model()), resolve_project_path should not re-anchor it to the
        project root.  We detect absolute paths and skip resolution.
        """
        p = Path(path_str)
        if p.is_absolute():
            return p
        return resolve_project_path(path_str)

    def _load_model(self) -> None:
        """Load ML model from disk."""
        model_path = self._resolve_path(self.config.model_path)

        if not model_path.exists():
            logger.warning(f"Model file not found: {self.config.model_path}")
            logger.info("Will operate in warmup mode until model is trained")
            self.model_loaded = False
            return

        try:
            if self.config.model_type == ModelType.ISOLATION_FOREST:
                import joblib  # type: ignore
                self.model = joblib.load(model_path)
                self.model_loaded = True
                logger.info(f"Loaded Isolation Forest from {model_path}")

            elif self.config.model_type == ModelType.XGBOOST:
                import xgboost as xgb  # type: ignore
                self.model = xgb.Booster()
                self.model.load_model(str(model_path))
                self.model_loaded = True
                logger.info(f"Loaded XGBoost from {model_path}")

            elif self.config.model_type == ModelType.ONE_CLASS_SVM:
                import joblib  # type: ignore
                self.model = joblib.load(model_path)
                self.model_loaded = True
                logger.info(f"Loaded One-Class SVM from {model_path}")

            elif self.config.model_type == ModelType.LSTM_AUTOENCODER:
                try:
                    from tensorflow import keras  # type: ignore
                    self.model = keras.models.load_model(model_path)
                    self.model_loaded = True
                    logger.info(f"Loaded LSTM Autoencoder from {model_path}")
                except ImportError:
                    logger.warning("TensorFlow not installed, LSTM Autoencoder unavailable")
                    self.model_loaded = False
                except Exception as exc:
                    logger.error(f"Failed to load LSTM model: {exc}")
                    self.model_loaded = False

            else:
                logger.error(f"Unsupported model type: {self.config.model_type}")
                self.model_loaded = False

        except ImportError as exc:
            logger.warning(f"Required library not installed: {exc}")
            self.model_loaded = False
        except Exception as exc:
            logger.error(f"Failed to load model: {exc}")
            self.model_loaded = False

    # ------------------------------------------------------------------
    # Pre-processing
    # ------------------------------------------------------------------

    def _preprocess_features(self, features: np.ndarray) -> np.ndarray:
        if features.ndim == 1:
            features = features.reshape(1, -1)
        features = np.nan_to_num(features, nan=0.0, posinf=1e6, neginf=-1e6)
        return np.clip(features, -1e6, 1e6)

    # ------------------------------------------------------------------
    # Per-model predictors
    # ------------------------------------------------------------------

    def _predict_isolation_forest(self, features: np.ndarray) -> Dict[str, Any]:
        predictions = self.model.predict(features)

        if hasattr(self.model, 'score_samples'):
            raw = -self.model.score_samples(features)
            raw_score = float(np.clip(raw, 0, None)[0])
        else:
            raw_score = 1.0 if predictions[0] == -1 else 0.0

        # Sigmoid-like compression: maps [0, ∞) → [0, 1)
        anomaly_score = raw_score / (1.0 + raw_score)

        is_anomaly = bool(predictions[0] == -1)

        # FIX BUG-16: When raw_score == 0 but the model still predicts -1
        # (anomaly), the old code produced confidence = 0.0, which was then
        # silently dropped by the confidence_threshold filter.  Clamp to a
        # minimum of 0.05 for anomalies so they are not invisibly suppressed.
        if is_anomaly:
            anomaly_score = max(anomaly_score, 0.05)

        confidence = anomaly_score if is_anomaly else 1.0 - anomaly_score
        confidence = float(min(0.95, max(0.05, confidence)))

        return {
            'is_attack': is_anomaly,
            'anomaly_score': anomaly_score,
            'confidence': confidence,
        }

    def _predict_xgboost(self, features: np.ndarray) -> Dict[str, Any]:
        import xgboost as xgb  # type: ignore

        dmatrix = xgb.DMatrix(features)
        raw_preds = self.model.predict(dmatrix)

        if raw_preds.ndim > 1:
            attack_prob = float(raw_preds[0][1]) if raw_preds.shape[1] > 1 else float(raw_preds[0][0])
        else:
            attack_prob = float(raw_preds[0])

        # FIX BUG-17: If the model was saved with output_margin=True, values
        # can exceed [0,1].  Clamp to a valid probability range.
        attack_prob = float(np.clip(attack_prob, 0.0, 1.0))

        is_attack = attack_prob > self.config.anomaly_threshold
        return {
            'is_attack': is_attack,
            'anomaly_score': attack_prob,
            'confidence': attack_prob if is_attack else 1.0 - attack_prob,
        }

    def _predict_one_class_svm(self, features: np.ndarray) -> Dict[str, Any]:
        predictions = self.model.predict(features)

        if hasattr(self.model, 'decision_function'):
            score = self.model.decision_function(features)
            # decision_function > 0 → inlier; < 0 → outlier (anomaly)
            # Convert to a [0,1] anomaly score via sigmoid
            anomaly_score = float(1.0 / (1.0 + np.exp(score[0])))
        else:
            anomaly_score = 0.5

        is_anomaly = bool(predictions[0] == -1)
        confidence = anomaly_score if is_anomaly else 1.0 - anomaly_score
        confidence = float(min(0.95, max(0.05, confidence)))

        return {
            'is_attack': is_anomaly,
            'anomaly_score': float(anomaly_score),
            'confidence': confidence,
        }

    def _predict_lstm_autoencoder(self, features: np.ndarray) -> Dict[str, Any]:
        """
        Predict using LSTM Autoencoder.

        FIX BUG-18: The original code created a sequence by placing the
        current feature vector only in the last timestep, with the rest
        zeroed out.  A model trained on real time-series would produce
        systematically high reconstruction errors for such a degenerate
        input, making every sample look anomalous.

        Fixed: maintain a rolling buffer (self._lstm_buffer) of the last
        sequence_length feature vectors.  The sequence is built from that
        buffer so the LSTM sees a realistic temporal context.
        """
        from tensorflow import keras  # type: ignore  # noqa: F401

        n_features = features.shape[-1]
        # Update rolling buffer with current sample
        self._lstm_buffer.append(features[0].copy())

        # Build the sequence (pad with zeros if buffer not yet full)
        seq = np.zeros(
            (1, self.config.sequence_length, n_features), dtype=features.dtype
        )
        for t, vec in enumerate(self._lstm_buffer):
            offset = self.config.sequence_length - len(self._lstm_buffer)
            seq[0, offset + t, :] = vec

        reconstructed = self.model.predict(seq, verbose=0)
        mse = float(np.mean(np.square(seq - reconstructed)))

        # Normalise MSE to [0,1]; cap at 0.5 by convention
        anomaly_score = min(1.0, mse / 0.5)
        is_attack = anomaly_score > self.config.anomaly_threshold
        confidence = anomaly_score if is_attack else 1.0 - anomaly_score
        confidence = float(min(0.95, max(0.05, confidence)))

        return {
            'is_attack': is_attack,
            'anomaly_score': anomaly_score,
            'confidence': confidence,
        }

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def detect(
        self, features: Union["TrafficFeaturesProtocol", np.ndarray]
    ) -> Optional[DetectionResult]:
        """
        Detect a DDoS attack using the loaded ML model.

        Returns None if the model is not loaded.
        """
        if not self.model_loaded:
            logger.debug("Model not loaded — skipping ML detection")
            return None

        start_time = time.time()

        try:
            feature_array = (
                features if isinstance(features, np.ndarray) else features.to_array()
            )
            processed = self._preprocess_features(feature_array)

            if self.config.model_type == ModelType.ISOLATION_FOREST:
                result = self._predict_isolation_forest(processed)
            elif self.config.model_type == ModelType.XGBOOST:
                result = self._predict_xgboost(processed)
            elif self.config.model_type == ModelType.ONE_CLASS_SVM:
                result = self._predict_one_class_svm(processed)
            elif self.config.model_type == ModelType.LSTM_AUTOENCODER:
                result = self._predict_lstm_autoencoder(processed)
            else:
                logger.error(f"Unsupported model type: {self.config.model_type}")
                return None

            inference_ms = (time.time() - start_time) * 1000
            self.stats['inference_times'].append(inference_ms)
            self.stats['average_inference_time_ms'] = float(
                np.mean(self.stats['inference_times'])
            )
            self.stats['detections'] += 1
            if result['is_attack']:
                self.stats['attacks_detected'] += 1

            detection_result = DetectionResult(
                is_attack=result['is_attack'],
                attack_type='ddos_ml' if result['is_attack'] else None,
                confidence=result['confidence'],
                anomaly_score=result['anomaly_score'],
                detection_time=time.time(),
                model_used=self.config.model_type.value,
                features_used=[],
            )

            self.detection_history.append(detection_result.__dict__)

            if self.config.enable_online_learning:
                self._check_online_learning()

            if (
                detection_result.is_attack
                and detection_result.confidence > self.config.confidence_threshold
            ):
                logger.info(
                    f"ML detection: attack (confidence={detection_result.confidence:.2f}, "
                    f"score={detection_result.anomaly_score:.3f})"
                )

            return detection_result

        except Exception as exc:
            logger.error(f"Error in ML detection: {exc}")
            return None

    def _check_online_learning(self) -> None:
        if time.time() - self.last_update_time > self.config.update_interval_seconds:
            self.last_update_time = time.time()
            logger.info("Online learning interval reached — retraining would happen here")

    def get_stats(self) -> Dict[str, Any]:
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

    def reload_model(self, model_path: Optional[str] = None) -> None:
        """Reload the model, optionally from a new path."""
        if model_path:
            self.config.model_path = model_path
        # FIX BUG-21: Reset the LSTM buffer when reloading so stale
        # history from the old model does not corrupt the new model's input.
        self._lstm_buffer.clear()
        self._load_model()