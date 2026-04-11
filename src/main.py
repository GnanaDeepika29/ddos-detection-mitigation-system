"""
Integration script for the DDoS detection and mitigation system.

This script demonstrates how the various components of the system work together:
1. TrafficCollector generates simulated network traffic
2. DetectionEngine analyzes traffic for potential DDoS attacks
3. MitigationEngine applies appropriate mitigation strategies
"""

from collector.traffic_collector import TrafficCollector
from detection.engine import DetectionEngine
from mitigation.engine import MitigationEngine

# Configuration for the detection engine
DETECTION_CONFIG = {
    "heuristic": {
        "enabled": True,
        "window_size": 10,  # Shorter window for faster detection
        "request_threshold": 50,
        "ip_threshold": 30,
        "traffic_spike_factor": 2.0
    }
}

# Configuration for the mitigation engine
MITIGATION_CONFIG = {
    "rate_limiting": {
        "enabled": True,
        "capacity": 20,  # Allow a small burst
        "refill_rate": 5  # Sustainable rate of 5 requests per second
    }
}

# Configuration for the traffic collector
TRAFFIC_CONFIG = {
    "normal_traffic_rate": 5,  # 5 requests per second
    "attack_traffic_rate": 50,  # 50 requests per second (attack)
    "attack_duration": 30,  # 30 seconds of attack
    "normal_ips": 5,  # 5 normal IP addresses
    "attack_ips": 3,  # 3 attack IP addresses
    "targets": ["192.168.1.100"]  # Single target IP
}

def process_request(source_ip, target_ip):
    """
    Process a single network request through the detection and mitigation pipeline.

    Args:
        source_ip (str): The source IP address of the request.
        target_ip (str): The target IP address of the request.
    """
    # Detect potential attack
    detection_result = detection_engine.detect(source_ip)

    # Apply mitigation if attack is detected
    if detection_result["is_attack"]:
        print(f"[ALERT] Potential {detection_result['attack_type']} attack detected from {source_ip} (confidence: {detection_result['confidence']:.2f})")
        
        # Check if the request should be blocked
        if not mitigation_engine.process_request(source_ip):
            print(f"[BLOCKED] Request from {source_ip} to {target_ip} blocked by mitigation engine")
            return

    # Allow the request if no attack is detected or mitigation allows it
    print(f"[ALLOWED] Request from {source_ip} to {target_ip} allowed")

if __name__ == "__main__":
    print("Initializing DDoS detection and mitigation system...")
    
    # Initialize the detection engine
    detection_engine = DetectionEngine(DETECTION_CONFIG)
    print("Detection engine initialized with heuristic detector")
    
    # Initialize the mitigation engine
    mitigation_engine = MitigationEngine(MITIGATION_CONFIG)
    print("Mitigation engine initialized with rate limiter")
    
    # Initialize the traffic collector
    traffic_collector = TrafficCollector(TRAFFIC_CONFIG)
    print("Traffic collector initialized")
    
    print("\nStarting simulation...")
    # Start the traffic simulation
    traffic_collector.start_simulation(process_request, duration=60)  # 60 seconds total
    
    print("\nSimulation completed. System performance:")
    print("- Detection: Heuristic-based detection with sliding time window")
    print("- Mitigation: Token bucket rate limiting")
    print("- Traffic: Mixed normal and attack traffic patterns")