"""
Ensemble Detector

Combines multiple detection methods to improve accuracy.
"""

import time
import logging
from collections import defaultdict, deque
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List, Tuple

from .threshold_detector import ThresholdDetector, ThresholdAlert, AttackType
from .ml_detector import MLDetector, DetectionResult
from .feature_extractor import FeatureExtractor, TrafficFeatures

logger = logging.getLogger(__name__)


class VotingStrategy(Enum):
    """Voting strategies for ensemble detection"""
    MAJORITY = "majority"
    WEIGHTED = "weighted"
    CONSENSUS = "consensus"
    HIERARCHICAL = "hierarchical"


@dataclass
class EnsembleConfig:
    """Configuration for ensemble detector"""
    voting_strategy: VotingStrategy = VotingStrategy.WEIGHTED
    threshold_weight: float = 0.4
    ml_weight: float = 0.4
    entropy_weight: float = 0.2
    min_confidence: float = 0.6
    min_agreeing_detectors: int = 2
    cascade_threshold_first: bool = True
    cascade_ml_threshold: float = 0.7
    cooldown_seconds: int = 10
    max_alerts_per_minute: int = 60


@dataclass
class EnsembleResult:
    """Result from ensemble detection"""
    is_attack: bool
    attack_type: str
    confidence: float
    severity: str
    detector_votes: Dict[str, Any]
    consensus_method: str
    timestamp: float
    affected_ips: List[str]
    details: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'is_attack': self.is_attack,
            'attack_type': self.attack_type,
            'confidence': self.confidence,
            'severity': self.severity,
            'detector_votes': self.detector_votes,
            'consensus_method': self.consensus_method,
            'timestamp': self.timestamp,
            'affected_ips': self.affected_ips[:10],
            'detector': 'ensemble',
        }


class EnsembleDetector:
    """
    Ensemble detector that combines multiple detection methods
    for improved accuracy and reduced false positives.
    """
    
    def __init__(self, config: Optional[EnsembleConfig] = None,
                 threshold_detector: Optional[ThresholdDetector] = None,
                 ml_detector: Optional[MLDetector] = None):
        self.config = config or EnsembleConfig()
        self.threshold_detector = threshold_detector or ThresholdDetector()
        self.ml_detector = ml_detector
        self.feature_extractor = FeatureExtractor()
        self.alert_history: deque = deque(maxlen=1000)
        self.alert_timestamps: List[float] = []
        self.stats = {
            'total_evaluations': 0, 
            'alerts_raised': 0, 
            'false_positives_estimated': 0
        }
        logger.info(f"EnsembleDetector initialized with strategy: {self.config.voting_strategy.value}")

    def _check_throttle(self) -> bool:
        """Check if alert throttling should be applied"""
        current_time = time.time()
        minute_ago = current_time - 60
        self.alert_timestamps = [ts for ts in self.alert_timestamps if ts > minute_ago]

        if len(self.alert_timestamps) >= self.config.max_alerts_per_minute:
            logger.warning("Alert rate limit reached")
            return False

        if self.alert_history and current_time - self.alert_history[-1].timestamp < self.config.cooldown_seconds:
            return False

        return True

    def _get_threshold_votes(self, features: TrafficFeatures) -> List[Dict[str, Any]]:
        """Get votes from threshold detector"""
        alerts = self.threshold_detector.detect(features)
        return [{
            'detector': 'threshold', 
            'attack_type': alert.attack_type.value,
            'confidence': alert.confidence, 
            'severity': alert.severity,
            'affected_ips': alert.affected_ips
        } for alert in alerts]

    def _get_ml_votes(self, features: TrafficFeatures) -> List[Dict[str, Any]]:
        """Get votes from ML detector"""
        if not self.ml_detector:
            return []

        result = self.ml_detector.detect(features)
        if result and result.is_attack and result.confidence > 0.5:
            return [{
                'detector': 'ml', 
                'attack_type': result.attack_type or 'ddos_ml',
                'confidence': result.confidence, 
                'severity': 'high' if result.confidence > 0.8 else 'medium',
                'affected_ips': []
            }]
        return []

    def _get_entropy_votes(self, features: TrafficFeatures) -> List[Dict[str, Any]]:
        """Get votes based on entropy analysis"""
        votes = []
        if features.entropy_src_ip < 0.6:
            confidence = min(0.9, 1 - (features.entropy_src_ip / 0.6))
            votes.append({
                'detector': 'entropy', 
                'attack_type': 'low_entropy_attack',
                'confidence': confidence, 
                'severity': 'medium',
                'affected_ips': [ip for ip, _ in features.top_dst_ips[:5]]
            })
        return votes

    def _weighted_vote(self, all_votes: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Perform weighted voting"""
        if not all_votes:
            return None

        weights = {
            'threshold': self.config.threshold_weight, 
            'ml': self.config.ml_weight, 
            'entropy': self.config.entropy_weight
        }
        attack_scores: Dict[str, float] = defaultdict(float)
        attack_details: Dict[str, Dict] = {}

        for vote in all_votes:
            weight = weights.get(vote['detector'], 0.1)
            attack_scores[vote['attack_type']] += vote['confidence'] * weight
            if (vote['attack_type'] not in attack_details or 
                vote['confidence'] > attack_details[vote['attack_type']]['confidence']):
                attack_details[vote['attack_type']] = vote

        if attack_scores:
            winning_attack = max(attack_scores.items(), key=lambda x: x[1])
            details = attack_details.get(winning_attack[0], {})
            raw_conf = details.get('confidence', 0)
            if raw_conf >= self.config.min_confidence:
                return {
                    'attack_type': winning_attack[0],
                    'confidence': min(0.95, raw_conf),
                    'severity': details.get('severity', 'medium'),
                    'affected_ips': details.get('affected_ips', []),
                }
        return None

    def _majority_vote(self, all_votes: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Perform majority voting"""
        if len(all_votes) < self.config.min_agreeing_detectors:
            return None
            
        best = max(all_votes, key=lambda x: x['confidence'])
        if best['confidence'] < self.config.min_confidence:
            return None
            
        return {
            'attack_type': best['attack_type'],
            'confidence': min(0.95, best['confidence']),
            'severity': best.get('severity', 'medium'),
            'affected_ips': best.get('affected_ips', []),
        }

    def _consensus_vote(self, all_votes: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Require consensus among all detectors"""
        if len(all_votes) < self.config.min_agreeing_detectors:
            return None
            
        types = {v['attack_type'] for v in all_votes}
        if len(types) != 1:
            return None
            
        attack_type = next(iter(types))
        avg_conf = sum(v['confidence'] for v in all_votes) / len(all_votes)
        if avg_conf < self.config.min_confidence:
            return None
            
        rank = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
        severity = max(
            (v.get('severity', 'medium') for v in all_votes),
            key=lambda s: rank.get(s, 1),
        )
        
        affected: List[str] = []
        for v in all_votes:
            if v.get('affected_ips'):
                affected = v['affected_ips']
                break
                
        return {
            'attack_type': attack_type,
            'confidence': min(0.95, avg_conf),
            'severity': severity,
            'affected_ips': affected,
        }

    def _hierarchical_detect(self, features: TrafficFeatures) -> Optional[Dict[str, Any]]:
        """Hierarchical detection: threshold first, then ML for confirmation"""
        threshold_alerts = self.threshold_detector.detect(features)

        if not threshold_alerts:
            return None

        if self.ml_detector:
            ml_result = self.ml_detector.detect(features)

            if ml_result and ml_result.is_attack and ml_result.confidence >= self.config.cascade_ml_threshold:
                best = max(threshold_alerts, key=lambda x: x.confidence)
                return {
                    'attack_type': best.attack_type.value,
                    'confidence': (best.confidence + ml_result.confidence) / 2,
                    'severity': best.severity, 
                    'affected_ips': best.affected_ips
                }
            elif ml_result and not ml_result.is_attack:
                self.stats['false_positives_estimated'] += 1
                return None

        # No ML confirmation, use threshold with reduced confidence
        best = max(threshold_alerts, key=lambda x: x.confidence)
        if best.confidence > 0.8:
            return {
                'attack_type': best.attack_type.value, 
                'confidence': best.confidence * 0.8,
                'severity': best.severity, 
                'affected_ips': best.affected_ips
            }
        return None

    def detect(self, features: TrafficFeatures) -> Optional[EnsembleResult]:
        """Run ensemble detection on traffic features"""
        self.stats['total_evaluations'] += 1

        # Collect votes from all detectors
        all_votes = []
        all_votes.extend(self._get_threshold_votes(features))
        all_votes.extend(self._get_ml_votes(features))
        all_votes.extend(self._get_entropy_votes(features))

        if not all_votes:
            return None

        # Apply voting strategy
        if self.config.voting_strategy == VotingStrategy.WEIGHTED:
            result = self._weighted_vote(all_votes)
        elif self.config.voting_strategy == VotingStrategy.HIERARCHICAL:
            result = self._hierarchical_detect(features)
        elif self.config.voting_strategy == VotingStrategy.MAJORITY:
            result = self._majority_vote(all_votes)
        elif self.config.voting_strategy == VotingStrategy.CONSENSUS:
            result = self._consensus_vote(all_votes)
        else:
            result = None

        if not result or result['confidence'] < self.config.min_confidence:
            return None

        # Check throttling
        if not self._check_throttle():
            return None

        # Create ensemble result
        ensemble_result = EnsembleResult(
            is_attack=True,
            attack_type=result['attack_type'],
            confidence=result['confidence'],
            severity=result['severity'],
            detector_votes={'total_votes': len(all_votes), 'votes': all_votes},
            consensus_method=self.config.voting_strategy.value,
            timestamp=time.time(),
            affected_ips=result.get('affected_ips', []),
            details={'window_size': features.window_size, 'packets_per_second': features.packets_per_second},
        )

        self.alert_history.append(ensemble_result)
        self.alert_timestamps.append(ensemble_result.timestamp)
        self.stats['alerts_raised'] += 1

        logger.info(f"Ensemble detection: {ensemble_result.attack_type} (confidence={ensemble_result.confidence:.2f})")
        return ensemble_result

    def detect_from_dict(self, aggregated_data: Dict[str, Any]) -> Optional[EnsembleResult]:
        """Convert aggregated window data to features and run ensemble detection."""
        metrics = aggregated_data.get('metrics', aggregated_data)
        window_size = int(
            aggregated_data.get('window_size_seconds')
            or aggregated_data.get('window_size')
            or metrics.get('window_size')
            or max(1, round(metrics.get('duration', 1)))
        )
        features = self.feature_extractor.extract_traffic_features(metrics, window_size)
        return self.detect(features)

    def get_stats(self) -> Dict[str, Any]:
        """Get ensemble detector statistics"""
        return {
            **self.stats, 
            'alert_history_size': len(self.alert_history),
            'voting_strategy': self.config.voting_strategy.value
        }
