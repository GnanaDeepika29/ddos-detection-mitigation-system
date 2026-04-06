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
    MAJORITY = "majority"
    WEIGHTED = "weighted"
    CONSENSUS = "consensus"
    HIERARCHICAL = "hierarchical"


@dataclass
class EnsembleConfig:
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
        # FIX BUG-6: 'details' field was present in __init__ but absent from
        # to_dict(), silently dropping diagnostic context on serialisation.
        return {
            'is_attack': self.is_attack,
            'attack_type': self.attack_type,
            'confidence': self.confidence,
            'severity': self.severity,
            'detector_votes': self.detector_votes,
            'consensus_method': self.consensus_method,
            'timestamp': self.timestamp,
            'affected_ips': self.affected_ips[:10],
            'details': self.details,        # FIX BUG-6
            'detector': 'ensemble',
        }


class EnsembleDetector:
    """
    Ensemble detector combining threshold, ML, and entropy signals.
    """

    def __init__(
        self,
        config: Optional[EnsembleConfig] = None,
        threshold_detector: Optional[ThresholdDetector] = None,
        ml_detector: Optional[MLDetector] = None,
    ) -> None:
        self.config = config or EnsembleConfig()
        self.threshold_detector = threshold_detector or ThresholdDetector()
        self.ml_detector = ml_detector
        self.feature_extractor = FeatureExtractor()
        self.alert_history: deque = deque(maxlen=1_000)
        # FIX BUG-7: Use a deque instead of a plain list to avoid rebuilding
        # the entire sequence on every _check_throttle() call.  maxlen caps
        # memory automatically and makes the sliding-window O(1).
        self.alert_timestamps: deque = deque(maxlen=self.config.max_alerts_per_minute * 2)
        self.stats: Dict[str, Any] = {
            'total_evaluations': 0,
            'alerts_raised': 0,
            'false_positives_estimated': 0,
        }
        logger.info(
            f"EnsembleDetector initialised with strategy: {self.config.voting_strategy.value}"
        )

    # ------------------------------------------------------------------
    # Throttle
    # ------------------------------------------------------------------

    def _check_throttle(self) -> bool:
        """Return True if an alert may be raised (not throttled)."""
        now = time.time()
        minute_ago = now - 60.0
        # FIX BUG-7: deque — drop elements from left until window is clean.
        while self.alert_timestamps and self.alert_timestamps[0] < minute_ago:
            self.alert_timestamps.popleft()

        if len(self.alert_timestamps) >= self.config.max_alerts_per_minute:
            logger.warning("Alert rate limit reached")
            return False

        if (
            self.alert_history
            and now - self.alert_history[-1].timestamp < self.config.cooldown_seconds
        ):
            return False

        return True

    # ------------------------------------------------------------------
    # Per-detector vote collectors
    # ------------------------------------------------------------------

    def _get_threshold_votes(self, features: TrafficFeatures) -> List[Dict[str, Any]]:
        alerts = self.threshold_detector.detect(features)
        return [
            {
                'detector': 'threshold',
                'attack_type': a.attack_type.value,
                'confidence': a.confidence,
                'severity': a.severity,
                'affected_ips': a.affected_ips,
            }
            for a in alerts
        ]

    def _get_ml_votes(self, features: TrafficFeatures) -> List[Dict[str, Any]]:
        if not self.ml_detector:
            return []
        result = self.ml_detector.detect(features)
        if result and result.is_attack and result.confidence > 0.5:
            return [
                {
                    'detector': 'ml',
                    'attack_type': result.attack_type or 'ddos_ml',
                    'confidence': result.confidence,
                    'severity': 'high' if result.confidence > 0.8 else 'medium',
                    'affected_ips': [],
                }
            ]
        return []

    def _get_entropy_votes(self, features: TrafficFeatures) -> List[Dict[str, Any]]:
        """
        Entropy-based vote.
        FIX BUG-41 (downstream): TrafficFeatures.entropy_src_ip is now
        normalised to [0,1] by FeatureExtractor, so this threshold (0.6)
        is now correctly comparable.  Previously raw Shannon-bit values
        (~2–5) were always > 0.6, so this branch never fired.
        """
        votes = []
        if features.entropy_src_ip < 0.6:
            confidence = min(0.9, 1.0 - features.entropy_src_ip / 0.6)
            votes.append(
                {
                    'detector': 'entropy',
                    'attack_type': 'low_entropy_attack',
                    'confidence': confidence,
                    'severity': 'medium',
                    'affected_ips': [ip for ip, _ in features.top_dst_ips[:5]],
                }
            )
        return votes

    # ------------------------------------------------------------------
    # Voting strategies
    # ------------------------------------------------------------------

    def _weighted_vote(self, all_votes: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Weighted ensemble vote.

        FIX BUG-2: The original code accumulated a weighted score per
        attack type but then returned the highest *individual detector
        confidence* (from attack_details) rather than the normalised
        ensemble score.  This produced confidence values that did not
        reflect the multi-detector agreement level.

        Fixed: the confidence returned is the normalised weighted sum
        (clamped to [0, 0.95]).  We also keep the best individual vote
        for severity and affected_ips metadata.
        """
        if not all_votes:
            return None

        weights = {
            'threshold': self.config.threshold_weight,
            'ml': self.config.ml_weight,
            'entropy': self.config.entropy_weight,
        }

        attack_scores: Dict[str, float] = defaultdict(float)
        attack_best_vote: Dict[str, Dict[str, Any]] = {}   # highest-confidence per type
        weight_totals: Dict[str, float] = defaultdict(float)

        for vote in all_votes:
            w = weights.get(vote['detector'], 0.1)
            attack_type = vote['attack_type']
            attack_scores[attack_type] += vote['confidence'] * w
            weight_totals[attack_type] += w
            # Track highest-confidence vote per type for metadata
            if (
                attack_type not in attack_best_vote
                or vote['confidence'] > attack_best_vote[attack_type]['confidence']
            ):
                attack_best_vote[attack_type] = vote

        if not attack_scores:
            return None

        winning_type = max(attack_scores, key=lambda t: attack_scores[t])
        total_w = weight_totals[winning_type]
        # Normalise: divide accumulated weighted score by total weight used
        ensemble_confidence = (
            attack_scores[winning_type] / total_w if total_w > 0 else 0.0
        )
        ensemble_confidence = min(0.95, ensemble_confidence)

        if ensemble_confidence < self.config.min_confidence:
            return None

        best = attack_best_vote[winning_type]
        return {
            'attack_type': winning_type,
            'confidence': ensemble_confidence,   # FIX BUG-2: ensemble score, not raw
            'severity': best.get('severity', 'medium'),
            'affected_ips': best.get('affected_ips', []),
        }

    def _majority_vote(self, all_votes: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Majority vote: an attack type must appear in >= min_agreeing_detectors
        distinct detector sources.

        FIX BUG-3: The original returned the single highest-confidence vote
        if total vote count >= min_agreeing_detectors, without checking
        whether those votes agreed on the *same attack type*.  Three detectors
        all flagging different attacks would trigger a false positive.

        Fixed: count distinct detectors per attack type; require that count
        to reach min_agreeing_detectors before raising an alert.
        """
        if not all_votes:
            return None

        # Group votes by attack type; collect distinct detectors per type
        type_detectors: Dict[str, set] = defaultdict(set)
        type_votes: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for v in all_votes:
            type_detectors[v['attack_type']].add(v['detector'])
            type_votes[v['attack_type']].append(v)

        # Find attack types with sufficient agreeing detectors
        qualified = {
            t: vs
            for t, vs in type_votes.items()
            if len(type_detectors[t]) >= self.config.min_agreeing_detectors
        }
        if not qualified:
            return None

        # Pick the type with the highest average confidence among qualifiers
        winning_type = max(
            qualified,
            key=lambda t: sum(v['confidence'] for v in qualified[t]) / len(qualified[t]),
        )
        votes_for_winner = qualified[winning_type]
        avg_conf = sum(v['confidence'] for v in votes_for_winner) / len(votes_for_winner)

        if avg_conf < self.config.min_confidence:
            return None

        best = max(votes_for_winner, key=lambda v: v['confidence'])
        return {
            'attack_type': winning_type,
            'confidence': min(0.95, avg_conf),
            'severity': best.get('severity', 'medium'),
            'affected_ips': best.get('affected_ips', []),
        }

    def _consensus_vote(self, all_votes: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Require all votes to agree on the same attack type."""
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
        affected: List[str] = next(
            (v['affected_ips'] for v in all_votes if v.get('affected_ips')), []
        )

        return {
            'attack_type': attack_type,
            'confidence': min(0.95, avg_conf),
            'severity': severity,
            'affected_ips': affected,
        }

    def _hierarchical_detect(self, features: TrafficFeatures) -> Optional[Dict[str, Any]]:
        """
        Hierarchical detection: threshold first, then ML for confirmation.

        FIX BUG-4 + BUG-5: In the original detect() method, all_votes were
        collected (calling threshold + ML + entropy) BEFORE the strategy
        branch was evaluated.  When HIERARCHICAL was selected, the collected
        votes were discarded and _hierarchical_detect() called the detectors
        AGAIN — double-running them, duplicating cooldown updates and wasting
        inference time.

        Now detect() skips vote collection for the HIERARCHICAL strategy and
        calls this method directly instead.
        """
        threshold_alerts = self.threshold_detector.detect(features)
        if not threshold_alerts:
            return None

        if self.ml_detector:
            ml_result = self.ml_detector.detect(features)

            if ml_result and ml_result.is_attack and ml_result.confidence >= self.config.cascade_ml_threshold:
                best = max(threshold_alerts, key=lambda a: a.confidence)
                return {
                    'attack_type': best.attack_type.value,
                    'confidence': min(0.95, (best.confidence + ml_result.confidence) / 2),
                    'severity': best.severity,
                    'affected_ips': best.affected_ips,
                }
            elif ml_result and not ml_result.is_attack:
                self.stats['false_positives_estimated'] += 1
                return None

        # No ML model or ML inconclusive — fall back to threshold with dampened confidence
        best = max(threshold_alerts, key=lambda a: a.confidence)
        if best.confidence > 0.8:
            return {
                'attack_type': best.attack_type.value,
                'confidence': best.confidence * 0.8,
                'severity': best.severity,
                'affected_ips': best.affected_ips,
            }
        return None

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def detect(self, features: TrafficFeatures) -> Optional[EnsembleResult]:
        """Run ensemble detection on traffic features."""
        self.stats['total_evaluations'] += 1

        # FIX BUG-4 / BUG-5: For HIERARCHICAL strategy, skip vote collection
        # and call _hierarchical_detect() directly to avoid double inference.
        if self.config.voting_strategy == VotingStrategy.HIERARCHICAL:
            result = self._hierarchical_detect(features)
            all_votes: List[Dict[str, Any]] = []   # no vote list in this path
        else:
            all_votes = []
            all_votes.extend(self._get_threshold_votes(features))
            all_votes.extend(self._get_ml_votes(features))
            all_votes.extend(self._get_entropy_votes(features))

            if not all_votes:
                return None

            if self.config.voting_strategy == VotingStrategy.WEIGHTED:
                result = self._weighted_vote(all_votes)
            elif self.config.voting_strategy == VotingStrategy.MAJORITY:
                result = self._majority_vote(all_votes)
            elif self.config.voting_strategy == VotingStrategy.CONSENSUS:
                result = self._consensus_vote(all_votes)
            else:
                result = None

        if not result or result['confidence'] < self.config.min_confidence:
            return None

        if not self._check_throttle():
            return None

        ensemble_result = EnsembleResult(
            is_attack=True,
            attack_type=result['attack_type'],
            confidence=result['confidence'],
            severity=result['severity'],
            detector_votes={'total_votes': len(all_votes), 'votes': all_votes},
            consensus_method=self.config.voting_strategy.value,
            timestamp=time.time(),
            affected_ips=result.get('affected_ips', []),
            details={
                'window_size': features.window_size,
                'packets_per_second': features.packets_per_second,
            },
        )

        self.alert_history.append(ensemble_result)
        self.alert_timestamps.append(ensemble_result.timestamp)
        self.stats['alerts_raised'] += 1

        logger.info(
            f"Ensemble detection: {ensemble_result.attack_type} "
            f"(confidence={ensemble_result.confidence:.2f}, "
            f"severity={ensemble_result.severity})"
        )
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
        return {
            **self.stats,
            'alert_history_size': len(self.alert_history),
            'voting_strategy': self.config.voting_strategy.value,
        }