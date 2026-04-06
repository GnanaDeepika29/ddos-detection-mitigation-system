"""
Model Drift Detection Module

Detects data drift and performance degradation in ML models.
"""

import logging
import numpy as np
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

try:
    from scipy.stats import ks_2samp, wasserstein_distance  # type: ignore
    SCIPY_AVAILABLE = True
except ImportError:
    SCIPY_AVAILABLE = False
    logging.warning("scipy not available. Install with: pip install scipy")

try:
    from sklearn.metrics import (  # type: ignore
        accuracy_score, precision_score, recall_score,
        f1_score, roc_auc_score, confusion_matrix,
    )
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logging.warning("scikit-learn not available. Install with: pip install scikit-learn")

try:
    import pandas as pd  # type: ignore  # noqa: F401
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class DriftMetrics:
    """Drift detection metrics for a single feature."""
    feature_name: str
    ks_statistic: float
    p_value: float
    wasserstein_distance: float
    drift_detected: bool
    drift_severity: str  # 'low' | 'medium' | 'high'
    # FIX BUG-27: default_factory=datetime.now().timestamp captured the bound
    # METHOD object at class-definition time, not a callable that returns a
    # float.  All instances would share the same stale reference.
    timestamp: float = field(default_factory=lambda: datetime.now().timestamp())

    def to_dict(self) -> Dict[str, Any]:
        return {
            'feature_name': self.feature_name,
            'ks_statistic': self.ks_statistic,
            'p_value': self.p_value,
            'wasserstein_distance': self.wasserstein_distance,
            'drift_detected': self.drift_detected,
            'drift_severity': self.drift_severity,
            'timestamp': self.timestamp,
        }


@dataclass
class PerformanceMetrics:
    """Model performance snapshot."""
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    auc_roc: Optional[float] = None
    # FIX BUG-28: same default_factory bug as DriftMetrics.timestamp.
    timestamp: float = field(default_factory=lambda: datetime.now().timestamp())

    def to_dict(self) -> Dict[str, Any]:
        return {
            'accuracy': self.accuracy,
            'precision': self.precision,
            'recall': self.recall,
            'f1_score': self.f1_score,
            'auc_roc': self.auc_roc,
            'timestamp': self.timestamp,
        }


@dataclass
class DegradationReport:
    """Performance degradation report for one metric."""
    metric_name: str
    current_value: float
    reference_value: float
    absolute_change: float
    relative_change: float
    degraded: bool
    degradation_level: str  # 'none' | 'slight' | 'moderate' | 'severe'


class ModelDriftDetector:
    """
    Detects drift in ML models for DDoS detection.

    Monitors covariate shift, performance degradation, and concept drift.
    """

    def __init__(
        self,
        reference_stats: Dict[str, Any],
        drift_threshold: float = 0.05,
    ) -> None:
        if not SCIPY_AVAILABLE:
            raise ImportError("scipy is required for drift detection")
        if not SKLEARN_AVAILABLE:
            raise ImportError("scikit-learn is required for performance monitoring")

        self.reference = reference_stats
        self.drift_threshold = drift_threshold
        self.drift_history: deque = deque(maxlen=1_000)
        self.performance_history: deque = deque(maxlen=1_000)

        self.severity_thresholds = {'low': 0.05, 'medium': 0.15, 'high': 0.25}
        self.degradation_thresholds = {
            'slight': -0.05,
            'moderate': -0.10,
            'severe': -0.20,
        }

        self._validate_reference_stats()
        logger.info(f"ModelDriftDetector initialised with drift_threshold={drift_threshold}")

    def _validate_reference_stats(self) -> None:
        if 'features' not in self.reference:
            raise ValueError("Reference stats must contain 'features' key")
        if 'performance' not in self.reference:
            raise ValueError("Reference stats must contain 'performance' key")
        if 'feature_names' not in self.reference:
            logger.warning("Reference stats missing 'feature_names', using indices")
            self.reference['feature_names'] = [
                f"feature_{i}" for i in range(self.reference['features'].shape[1])
            ]

    def _calculate_drift_severity(self, ks_statistic: float) -> str:
        if ks_statistic < self.severity_thresholds['low']:
            return 'low'
        if ks_statistic < self.severity_thresholds['medium']:
            return 'medium'
        return 'high'

    # ------------------------------------------------------------------
    # Covariate shift
    # ------------------------------------------------------------------

    def detect_covariate_shift(
        self,
        current_batch: np.ndarray,
        feature_names: Optional[List[str]] = None,
    ) -> Dict[str, DriftMetrics]:
        """
        Detect changes in input feature distribution (KS test + Wasserstein).

        FIX BUG-31: detect_covariate_shift() now automatically appends its
        result to self.drift_history so should_retrain() sees actual data
        without requiring callers to separately call add_drift_result().
        add_drift_result() is kept for manual / test use.
        """
        ref_shape = self.reference['features'].shape[1]
        if current_batch.shape[1] != ref_shape:
            raise ValueError(
                f"Feature dimension mismatch: {current_batch.shape[1]} vs {ref_shape}"
            )

        names = feature_names or self.reference['feature_names']
        drift_results: Dict[str, DriftMetrics] = {}

        for i, feature in enumerate(names):
            ref_dist = self.reference['features'][:, i]
            curr_dist = current_batch[:, i]

            ks_stat, p_value = ks_2samp(ref_dist, curr_dist)
            emd = wasserstein_distance(ref_dist, curr_dist)
            drift_detected = ks_stat > self.drift_threshold
            severity = self._calculate_drift_severity(ks_stat)

            drift_results[feature] = DriftMetrics(
                feature_name=feature,
                ks_statistic=float(ks_stat),
                p_value=float(p_value),
                wasserstein_distance=float(emd),
                drift_detected=drift_detected,
                drift_severity=severity,
                timestamp=datetime.now().timestamp(),
            )

        drifted = [f for f, m in drift_results.items() if m.drift_detected]
        if drifted:
            logger.warning(f"Covariate shift detected in features: {drifted}")
        else:
            logger.debug("No covariate shift detected")

        # FIX BUG-31: auto-append so should_retrain() has data to evaluate.
        self.drift_history.append(drift_results)
        return drift_results

    # ------------------------------------------------------------------
    # Performance degradation
    # ------------------------------------------------------------------

    def detect_performance_degradation(
        self,
        y_true: np.ndarray,
        y_pred: np.ndarray,
        y_scores: Optional[np.ndarray] = None,
    ) -> Dict[str, DegradationReport]:
        """Monitor model performance metrics against reference values."""
        current_metrics: Dict[str, Any] = {
            'accuracy': accuracy_score(y_true, y_pred),
            'precision': precision_score(y_true, y_pred, zero_division=0),
            'recall': recall_score(y_true, y_pred, zero_division=0),
            'f1_score': f1_score(y_true, y_pred, zero_division=0),
        }

        if y_scores is not None:
            try:
                current_metrics['auc_roc'] = roc_auc_score(y_true, y_scores)
            except Exception as exc:
                logger.warning(f"Failed to calculate AUC: {exc}")
                current_metrics['auc_roc'] = None

        ref_metrics = self.reference['performance']
        degradation_results: Dict[str, DegradationReport] = {}

        for name, current_value in current_metrics.items():
            if name not in ref_metrics or current_value is None:
                continue
            reference_value = ref_metrics[name]
            if reference_value is None:
                continue

            absolute_change = current_value - reference_value
            relative_change = (
                absolute_change / reference_value if reference_value != 0 else 0.0
            )

            degraded = relative_change < 0
            degradation_level = 'none'
            if degraded:
                if relative_change < self.degradation_thresholds['severe']:
                    degradation_level = 'severe'
                elif relative_change < self.degradation_thresholds['moderate']:
                    degradation_level = 'moderate'
                elif relative_change < self.degradation_thresholds['slight']:
                    degradation_level = 'slight'

            degradation_results[name] = DegradationReport(
                metric_name=name,
                current_value=float(current_value),
                reference_value=float(reference_value),
                absolute_change=float(absolute_change),
                relative_change=float(relative_change),
                degraded=degraded,
                degradation_level=degradation_level,
            )

        perf = PerformanceMetrics(
            accuracy=current_metrics['accuracy'],
            precision=current_metrics['precision'],
            recall=current_metrics['recall'],
            f1_score=current_metrics['f1_score'],
            auc_roc=current_metrics.get('auc_roc'),
        )
        self.performance_history.append(perf)

        degraded = [r for r in degradation_results.values() if r.degraded]
        for r in degraded:
            logger.warning(
                f"Performance degradation in {r.metric_name}: "
                f"{r.relative_change * 100:.1f}% drop ({r.degradation_level})"
            )
        if not degraded:
            logger.debug("No performance degradation detected")

        return degradation_results

    # ------------------------------------------------------------------
    # Concept drift
    # ------------------------------------------------------------------

    def detect_concept_drift(
        self,
        current_predictions: np.ndarray,
        labels: np.ndarray,
        window_size: int = 1_000,
    ) -> bool:
        """
        Detect concept drift by analysing changes in the confusion matrix.

        FIX BUG-29: The original code used np.zeros(1000) as a fallback for
        missing reference labels/predictions.  An all-zero confusion matrix
        produces ref_fpr = 0 and ref_fnr = 0; any real model output then
        shows a change > 0.1, triggering spurious concept-drift alerts.

        Fixed: return False immediately if reference labels/predictions are
        absent — we cannot detect drift without a valid baseline.
        """
        if (
            'labels' not in self.reference
            or 'predictions' not in self.reference
        ):
            logger.debug(
                "Concept drift detection skipped: reference 'labels'/'predictions' absent"
            )
            return False

        if len(current_predictions) < window_size:
            return False

        ref_cm = confusion_matrix(
            self.reference['labels'],
            self.reference['predictions'],
        )
        curr_cm = confusion_matrix(
            labels[-window_size:],
            current_predictions[-window_size:],
        )

        def _safe_rate(cm: np.ndarray, row: int, col: int) -> float:
            row_total = cm[row, :].sum()
            return float(cm[row, col]) / row_total if row_total > 0 else 0.0

        ref_fpr = _safe_rate(ref_cm, 0, 1)
        curr_fpr = _safe_rate(curr_cm, 0, 1)
        ref_fnr = _safe_rate(ref_cm, 1, 0)
        curr_fnr = _safe_rate(curr_cm, 1, 0)

        fpr_change = abs(curr_fpr - ref_fpr)
        fnr_change = abs(curr_fnr - ref_fnr)
        drift_detected = fpr_change > 0.1 or fnr_change > 0.1

        if drift_detected:
            logger.warning(
                f"Concept drift detected: FPR Δ={fpr_change:.3f}, FNR Δ={fnr_change:.3f}"
            )
        return drift_detected

    # ------------------------------------------------------------------
    # Retraining decision
    # ------------------------------------------------------------------

    def should_retrain(
        self,
        drift_history_window: int = 10,
        performance_window: int = 10,
        drift_ratio_threshold: float = 0.3,
        degradation_ratio_threshold: float = 0.3,
    ) -> bool:
        """Determine if the model should be retrained based on recent signals."""
        recent_drifts = list(self.drift_history)[-drift_history_window:]
        covariate_drift = False

        if recent_drifts:
            total_checks = 0
            drift_count = 0
            for batch in recent_drifts:
                if isinstance(batch, dict):
                    for metrics in batch.values():
                        if hasattr(metrics, 'drift_detected'):
                            total_checks += 1
                            if metrics.drift_detected:
                                drift_count += 1
            if total_checks > 0:
                covariate_drift = (drift_count / total_checks) > drift_ratio_threshold

        recent_perf = list(self.performance_history)[-performance_window:]
        performance_degraded = False

        if recent_perf:
            avg_acc = np.mean([p.accuracy for p in recent_perf])
            ref_acc = self.reference['performance'].get('accuracy', 0)
            if ref_acc > 0:
                performance_degraded = (
                    (ref_acc - avg_acc) / ref_acc
                ) > degradation_ratio_threshold

        should = covariate_drift or performance_degraded
        if should:
            reasons = []
            if covariate_drift:
                reasons.append("covariate shift")
            if performance_degraded:
                reasons.append("performance degradation")
            logger.warning(f"Model should be retrained: {', '.join(reasons)}")
        return should

    # ------------------------------------------------------------------
    # History management
    # ------------------------------------------------------------------

    def add_drift_result(self, drift_results: Dict[str, "DriftMetrics"]) -> None:
        """Manually add a drift result to history (e.g. from external checks)."""
        self.drift_history.append(drift_results)

    def get_drift_summary(self) -> Dict[str, Any]:
        """Return a JSON-serialisable drift summary."""
        if not self.drift_history:
            return {'total_checks': 0, 'drift_detected': False}

        total_checks = len(self.drift_history)
        drift_count = 0
        for batch in self.drift_history:
            if isinstance(batch, dict):
                for m in batch.values():
                    if hasattr(m, 'drift_detected') and m.drift_detected:
                        drift_count += 1
                        break

        recent_batches = list(self.drift_history)[-5:]

        # FIX BUG-32: Serialise DriftMetrics dataclasses to plain dicts so
        # the summary is JSON-serialisable without a custom encoder.
        serialisable_recent = []
        for batch in recent_batches:
            if isinstance(batch, dict):
                serialisable_recent.append(
                    {k: (v.to_dict() if hasattr(v, 'to_dict') else v) for k, v in batch.items()}
                )
            else:
                serialisable_recent.append(batch)

        return {
            'total_checks': total_checks,
            'drift_detected': drift_count > 0,
            'drift_frequency': drift_count / total_checks if total_checks > 0 else 0.0,
            'recent_drifts': serialisable_recent,   # FIX BUG-32
        }

    def get_performance_summary(self) -> Dict[str, Any]:
        if not self.performance_history:
            return {'total_checks': 0}
        recent = list(self.performance_history)[-10:]
        return {
            'total_checks': len(self.performance_history),
            'current_accuracy': recent[-1].accuracy if recent else 0.0,
            'avg_accuracy_last_10': float(np.mean([p.accuracy for p in recent])),
            'accuracy_trend': self._calculate_trend([p.accuracy for p in recent]),
            'performance_history': [p.to_dict() for p in recent],
        }

    def _calculate_trend(self, values: List[float]) -> str:
        if len(values) < 2:
            return 'stable'
        x = np.arange(len(values))
        slope = float(np.polyfit(x, values, 1)[0])
        if slope > 0.01:
            return 'increasing'
        if slope < -0.01:
            return 'decreasing'
        return 'stable'

    def reset(self) -> None:
        self.drift_history.clear()
        self.performance_history.clear()
        logger.info("Drift detector history reset")


def create_reference_stats(
    training_features: np.ndarray,
    training_labels: np.ndarray,
    training_predictions: np.ndarray,
    performance_metrics: Dict[str, float],
) -> Dict[str, Any]:
    """Create reference statistics from training data."""
    return {
        'features': training_features,
        'labels': training_labels,
        'predictions': training_predictions,
        'performance': performance_metrics,
        'feature_names': [f"feature_{i}" for i in range(training_features.shape[1])],
        'created_at': datetime.now().timestamp(),
    }