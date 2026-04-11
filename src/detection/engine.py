"""
The core detection engine that coordinates multiple detection strategies.
"""

from .heuristic_detector import HeuristicDetector

class DetectionEngine:
    """
    Orchestrates multiple DDoS detection strategies.

    This engine serves as the central point for applying different detection
    techniques. It can be configured with multiple detectors, such as
    heuristic-based detectors, machine learning models, and rule-based systems.
    The engine combines results from all detectors to make a final decision.
    """
    def __init__(self, config: dict):
        """
        Initializes the DetectionEngine with a given configuration.

        Args:
            config (dict): A configuration dictionary. For example:
                           {
                               "heuristic": {
                                   "enabled": True,
                                   "window_size": 60,
                                   "request_threshold": 100,
                                   "ip_threshold": 50,
                                   "traffic_spike_factor": 2.0
                               },
                               "ml": {
                                   "enabled": False
                                   # ML-specific configuration would go here
                               }
                           }
        """
        self.config = config
        self.detectors = []

        # Initialize heuristic detector if enabled
        if self.config.get("heuristic", {}).get("enabled"):
            heuristic_config = self.config["heuristic"]
            self.detectors.append(HeuristicDetector(heuristic_config))

        # Future detectors can be initialized here
        # For example:
        # if self.config.get("ml", {}).get("enabled"):
        #     ml_config = self.config["ml"]
        #     self.detectors.append(MLDetector(ml_config))

    def detect(self, ip_address: str) -> dict:
        """
        Analyzes traffic from an IP address using all enabled detection strategies.

        Args:
            ip_address (str): The IP address of the request source.

        Returns:
            dict: A dictionary containing aggregated detection results. For example:
                  {
                      "is_attack": True,
                      "attack_type": "flood",
                      "confidence": 0.85,
                      "details": {
                          "heuristic": {
                              "is_attack": True,
                              "attack_type": "targeted_flood",
                              "details": {...}
                          },
                          "ml": {
                              "is_attack": False,
                              "confidence": 0.3
                          }
                      }
                  }
        """
        results = {}
        is_attack = False
        attack_type = None
        confidence = 0.0

        # Run detection through all enabled detectors
        for detector in self.detectors:
            detector_name = detector.__class__.__name__.lower().replace("detector", "")
            detector_result = detector.detect(ip_address)
            results[detector_name] = detector_result

            # Update overall result based on detector output
            if detector_result["is_attack"]:
                is_attack = True
                if detector_result["attack_type"]:
                    attack_type = detector_result["attack_type"]
                # Simple confidence calculation: count of positive detectors / total detectors
                confidence = sum(1 for r in results.values() if r["is_attack"])
                confidence /= len(self.detectors)

        return {
            "is_attack": is_attack,
            "attack_type": attack_type,
            "confidence": confidence,
            "details": results
        }