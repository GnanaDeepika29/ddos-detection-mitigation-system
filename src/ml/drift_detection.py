"""
Model Drift Detection Module

Detects data drift and performance degradation in ML models.
Supports:
- Covariate shift detection (KS test, Wasserstein distance)
- Performance degradation monitoring
- Concept drift detection
- Automatic retraining triggers
"""

import numpy as np
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import deque

# Lazy imports for optional dependencies
try:
    from scipy.stats import ks_2samp, wasserstein_distance
    SCIPY_AVAILABLE = True
except ImportError:
    SCIPY_AVAILABLE = False
    logging.warning("scipy not available. Install with: pip install scipy")

try:
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score, 
        f1_score, roc_auc_score, confusion_matrix
    )
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logging.warning("scikit-learn not available. Install with: pip install scikit-learn")

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False
    logging.warning("pandas not available. Install with: pip install pandas")

logger = logging.getLogger(__name__)


@dataclass
class DriftMetrics:
    """Drift detection metrics for a feature"""
    feature_name: str
    ks_statistic: float
    p_value: float
    wasserstein_distance: float
    drift_detected: bool
    drift_severity: str  # 'low', 'medium', 'high'
    timestamp: float = field(default_factory=datetime.now().timestamp)


@dataclass
class PerformanceMetrics:
    """Performance metrics for model evaluation"""
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    auc_roc: Optional[float] = None
    timestamp: float = field(default_factory=datetime.now().timestamp)
    
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
    """Performance degradation report"""
    metric_name: str
    current_value: float
    reference_value: float
    absolute_change: float
    relative_change: float
    degraded: bool
    degradation_level: str  # 'none', 'slight', 'moderate', 'severe'


class ModelDriftDetector:
    """
    Detects drift in ML models for DDoS detection.
    
    Monitors:
    - Covariate shift (input distribution changes)
    - Performance degradation
    - Concept drift
    """
    
    def __init__(self, reference_stats: Dict[str, Any], drift_threshold: float = 0.05):
        """
        Initialize drift detector.
        
        Args:
            reference_stats: Dictionary containing reference statistics:
                - 'features': Reference feature matrix (numpy array)
                - 'performance': Reference performance metrics
                - 'feature_names': List of feature names
            drift_threshold: Threshold for drift detection (KS statistic)
        """
        if not SCIPY_AVAILABLE:
            raise ImportError("scipy is required for drift detection")
        if not SKLEARN_AVAILABLE:
            raise ImportError("scikit-learn is required for performance monitoring")
            
        self.reference = reference_stats
        self.drift_threshold = drift_threshold
        self.drift_history: deque = deque(maxlen=1000)
        self.performance_history: deque = deque(maxlen=1000)
        
        # Drift severity thresholds
        self.severity_thresholds = {
            'low': 0.05,
            'medium': 0.15,
            'high': 0.25
        }
        
        # Performance degradation thresholds (relative change)
        self.degradation_thresholds = {
            'slight': -0.05,   # 5% drop
            'moderate': -0.10,  # 10% drop
            'severe': -0.20     # 20% drop
        }
        
        # Validate reference stats
        self._validate_reference_stats()
        
        logger.info(f"ModelDriftDetector initialized with drift_threshold={drift_threshold}")
    
    def _validate_reference_stats(self):
        """Validate reference statistics structure"""
        if 'features' not in self.reference:
            raise ValueError("Reference stats must contain 'features' key")
        
        if 'performance' not in self.reference:
            raise ValueError("Reference stats must contain 'performance' key")
        
        if 'feature_names' not in self.reference:
            logger.warning("Reference stats missing 'feature_names', using indices")
            self.reference['feature_names'] = [f"feature_{i}" for i in range(self.reference['features'].shape[1])]
    
    def _calculate_drift_severity(self, ks_statistic: float) -> str:
        """Calculate drift severity based on KS statistic"""
        if ks_statistic < self.severity_thresholds['low']:
            return 'low'
        elif ks_statistic < self.severity_thresholds['medium']:
            return 'medium'
        else:
            return 'high'
    
    def detect_covariate_shift(self, current_batch: np.ndarray, 
                                feature_names: Optional[List[str]] = None) -> Dict[str, DriftMetrics]:
        """
        Detect changes in input feature distribution.
        
        Args:
            current_batch: Current batch of features (n_samples x n_features)
            feature_names: Optional list of feature names
            
        Returns:
            Dictionary of drift metrics per feature
        """
        if current_batch.shape[1] != self.reference['features'].shape[1]:
            raise ValueError(f"Feature dimension mismatch: {current_batch.shape[1]} vs {self.reference['features'].shape[1]}")
        
        drift_results = {}
        feature_names = feature_names or self.reference['feature_names']
        
        for i, feature in enumerate(feature_names):
            # Get reference and current distributions
            ref_dist = self.reference['features'][:, i]
            curr_dist = current_batch[:, i]
            
            # Kolmogorov-Smirnov test
            ks_stat, p_value = ks_2samp(ref_dist, curr_dist)
            
            # Wasserstein distance (Earth Mover's Distance)
            emd = wasserstein_distance(ref_dist, curr_dist)
            
            # Determine drift severity
            drift_detected = ks_stat > self.drift_threshold
            severity = self._calculate_drift_severity(ks_stat)
            
            drift_results[feature] = DriftMetrics(
                feature_name=feature,
                ks_statistic=float(ks_stat),
                p_value=float(p_value),
                wasserstein_distance=float(emd),
                drift_detected=drift_detected,
                drift_severity=severity,
                timestamp=datetime.now().timestamp()
            )
        
        # Log drift summary
        drifted_features = [f for f, m in drift_results.items() if m.drift_detected]
        if drifted_features:
            logger.warning(f"Covariate shift detected in features: {drifted_features}")
        else:
            logger.debug("No covariate shift detected")
        
        return drift_results
    
    def detect_performance_degradation(self, y_true: np.ndarray, y_pred: np.ndarray,
                                        y_scores: Optional[np.ndarray] = None) -> Dict[str, DegradationReport]:
        """
        Monitor model performance metrics.
        
        Args:
            y_true: Ground truth labels
            y_pred: Predicted labels
            y_scores: Prediction scores/probabilities (for AUC)
            
        Returns:
            Dictionary of degradation reports per metric
        """
        # Calculate current metrics
        current_metrics = {
            'accuracy': accuracy_score(y_true, y_pred),
            'precision': precision_score(y_true, y_pred, zero_division=0),
            'recall': recall_score(y_true, y_pred, zero_division=0),
            'f1_score': f1_score(y_true, y_pred, zero_division=0),
        }
        
        # Calculate AUC if scores provided
        if y_scores is not None:
            try:
                current_metrics['auc_roc'] = roc_auc_score(y_true, y_scores)
            except Exception as e:
                logger.warning(f"Failed to calculate AUC: {e}")
                current_metrics['auc_roc'] = None
        
        # Get reference metrics
        ref_metrics = self.reference['performance']
        
        # Calculate degradation
        degradation_results = {}
        
        for metric_name, current_value in current_metrics.items():
            if metric_name not in ref_metrics:
                logger.warning(f"Reference metric {metric_name} not found, skipping")
                continue
            
            reference_value = ref_metrics[metric_name]
            
            # Skip None values
            if current_value is None or reference_value is None:
                continue
            
            absolute_change = current_value - reference_value
            relative_change = absolute_change / reference_value if reference_value != 0 else 0
            
            # Determine degradation level
            degraded = relative_change < 0
            degradation_level = 'none'
            
            if degraded:
                if relative_change < self.degradation_thresholds['severe']:
                    degradation_level = 'severe'
                elif relative_change < self.degradation_thresholds['moderate']:
                    degradation_level = 'moderate'
                elif relative_change < self.degradation_thresholds['slight']:
                    degradation_level = 'slight'
            
            degradation_results[metric_name] = DegradationReport(
                metric_name=metric_name,
                current_value=float(current_value),
                reference_value=float(reference_value),
                absolute_change=float(absolute_change),
                relative_change=float(relative_change),
                degraded=degraded,
                degradation_level=degradation_level
            )
        
        # Create performance metrics object for history
        perf_metrics = PerformanceMetrics(
            accuracy=current_metrics['accuracy'],
            precision=current_metrics['precision'],
            recall=current_metrics['recall'],
            f1_score=current_metrics['f1_score'],
            auc_roc=current_metrics.get('auc_roc'),
            timestamp=datetime.now().timestamp()
        )
        
        self.performance_history.append(perf_metrics)
        
        # Log degradation
        degraded_metrics = [m for m in degradation_results.values() if m.degraded]
        if degraded_metrics:
            for metric in degraded_metrics:
                logger.warning(f"Performance degradation in {metric.metric_name}: "
                             f"{metric.relative_change*100:.1f}% drop ({metric.degradation_level})")
        else:
            logger.debug("No performance degradation detected")
        
        return degradation_results
    
    def detect_concept_drift(self, current_predictions: np.ndarray,
                              labels: np.ndarray,
                              window_size: int = 1000) -> bool:
        """
        Detect concept drift by analyzing prediction-label relationship.
        
        Args:
            current_predictions: Model predictions
            labels: True labels
            window_size: Size of sliding window for analysis
            
        Returns:
            True if concept drift detected
        """
        if len(current_predictions) < window_size:
            return False
        
        # Get reference confusion matrix
        ref_cm = confusion_matrix(
            self.reference.get('labels', np.zeros(1000)), 
            self.reference.get('predictions', np.zeros(1000))
        )
        
        # Calculate current confusion matrix
        curr_cm = confusion_matrix(labels[-window_size:], current_predictions[-window_size:])
        
        # Calculate change in false positive rate
        ref_fpr = ref_cm[0, 1] / (ref_cm[0, 0] + ref_cm[0, 1]) if (ref_cm[0, 0] + ref_cm[0, 1]) > 0 else 0
        curr_fpr = curr_cm[0, 1] / (curr_cm[0, 0] + curr_cm[0, 1]) if (curr_cm[0, 0] + curr_cm[0, 1]) > 0 else 0
        
        # Calculate change in false negative rate
        ref_fnr = ref_cm[1, 0] / (ref_cm[1, 0] + ref_cm[1, 1]) if (ref_cm[1, 0] + ref_cm[1, 1]) > 0 else 0
        curr_fnr = curr_cm[1, 0] / (curr_cm[1, 0] + curr_cm[1, 1]) if (curr_cm[1, 0] + curr_cm[1, 1]) > 0 else 0
        
        # Significant change in error patterns indicates concept drift
        fpr_change = abs(curr_fpr - ref_fpr)
        fnr_change = abs(curr_fnr - ref_fnr)
        
        concept_drift_detected = fpr_change > 0.1 or fnr_change > 0.1
        
        if concept_drift_detected:
            logger.warning(f"Concept drift detected: FPR change={fpr_change:.3f}, FNR change={fnr_change:.3f}")
        
        return concept_drift_detected
    
    def should_retrain(self, drift_history_window: int = 10, 
                       performance_window: int = 10,
                       drift_ratio_threshold: float = 0.3,
                       degradation_ratio_threshold: float = 0.3) -> bool:
        """
        Determine if model needs retraining based on recent drift history.
        
        Args:
            drift_history_window: Number of recent drift checks to analyze
            performance_window: Number of recent performance checks to analyze
            drift_ratio_threshold: Ratio of drifted features that triggers retraining
            degradation_ratio_threshold: Ratio of degraded metrics that triggers retraining
            
        Returns:
            True if model should be retrained
        """
        # Check covariate shift
        recent_drifts = list(self.drift_history)[-drift_history_window:]
        
        if recent_drifts:
            # Count features that drifted in each batch
            total_feature_checks = 0
            total_drift_count = 0
            
            for drift_batch in recent_drifts:
                if isinstance(drift_batch, dict):
                    for feature, metrics in drift_batch.items():
                        if hasattr(metrics, 'drift_detected'):
                            total_feature_checks += 1
                            if metrics.drift_detected:
                                total_drift_count += 1
            
            if total_feature_checks > 0:
                drift_ratio = total_drift_count / total_feature_checks
                covariate_drift_detected = drift_ratio > drift_ratio_threshold
            else:
                covariate_drift_detected = False
        else:
            covariate_drift_detected = False
        
        # Check performance degradation
        recent_performance = list(self.performance_history)[-performance_window:]
        
        if recent_performance:
            degraded_metrics_count = 0
            total_metrics_count = 0
            
            # This would need to track degradation per metric
            # Simplified: check if recent performance is significantly below reference
            recent_accuracies = [p.accuracy for p in recent_performance]
            avg_recent_accuracy = np.mean(recent_accuracies)
            ref_accuracy = self.reference['performance'].get('accuracy', 0)
            
            if ref_accuracy > 0:
                accuracy_degradation = (ref_accuracy - avg_recent_accuracy) / ref_accuracy
                performance_degraded = accuracy_degradation > degradation_ratio_threshold
            else:
                performance_degraded = False
        else:
            performance_degraded = False
        
        # Combine signals
        should_retrain = covariate_drift_detected or performance_degraded
        
        if should_retrain:
            reasons = []
            if covariate_drift_detected:
                reasons.append("covariate shift")
            if performance_degraded:
                reasons.append("performance degradation")
            logger.warning(f"Model should be retrained due to: {', '.join(reasons)}")
        
        return should_retrain
    
    def add_drift_result(self, drift_results: Dict[str, DriftMetrics]):
        """Add drift detection result to history"""
        self.drift_history.append(drift_results)
    
    def get_drift_summary(self) -> Dict[str, Any]:
        """Get summary of drift detection history"""
        if not self.drift_history:
            return {'total_checks': 0, 'drift_detected': False}
        
        total_checks = len(self.drift_history)
        drift_detected_count = 0
        
        for batch in self.drift_history:
            if isinstance(batch, dict):
                for metrics in batch.values():
                    if hasattr(metrics, 'drift_detected') and metrics.drift_detected:
                        drift_detected_count += 1
                        break
        
        return {
            'total_checks': total_checks,
            'drift_detected': drift_detected_count > 0,
            'drift_frequency': drift_detected_count / total_checks if total_checks > 0 else 0,
            'recent_drifts': list(self.drift_history)[-5:],
        }
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get summary of performance history"""
        if not self.performance_history:
            return {'total_checks': 0}
        
        recent_perf = list(self.performance_history)[-10:]
        
        return {
            'total_checks': len(self.performance_history),
            'current_accuracy': recent_perf[-1].accuracy if recent_perf else 0,
            'avg_accuracy_last_10': np.mean([p.accuracy for p in recent_perf]),
            'accuracy_trend': self._calculate_trend([p.accuracy for p in recent_perf]),
            'performance_history': [p.to_dict() for p in recent_perf],
        }
    
    def _calculate_trend(self, values: List[float]) -> str:
        """Calculate trend of values (increasing, decreasing, stable)"""
        if len(values) < 2:
            return 'stable'
        
        # Simple linear trend
        x = np.arange(len(values))
        slope = np.polyfit(x, values, 1)[0]
        
        if slope > 0.01:
            return 'increasing'
        elif slope < -0.01:
            return 'decreasing'
        else:
            return 'stable'
    
    def reset(self):
        """Reset drift history"""
        self.drift_history.clear()
        self.performance_history.clear()
        logger.info("Drift detector history reset")


def create_reference_stats(training_features: np.ndarray, 
                           training_labels: np.ndarray,
                           training_predictions: np.ndarray,
                           performance_metrics: Dict[str, float]) -> Dict[str, Any]:
    """
    Create reference statistics from training data.
    
    Args:
        training_features: Training feature matrix
        training_labels: Training labels
        training_predictions: Training predictions (for confusion matrix)
        performance_metrics: Performance metrics on validation set
        
    Returns:
        Dictionary of reference statistics
    """
    return {
        'features': training_features,
        'labels': training_labels,
        'predictions': training_predictions,
        'performance': performance_metrics,
        'feature_names': [f"feature_{i}" for i in range(training_features.shape[1])],
        'created_at': datetime.now().timestamp(),
    }