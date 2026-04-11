"""
Implements heuristic-based DDoS detection logic.
"""

import time
from collections import defaultdict, deque
from threading import Lock

class HeuristicDetector:
    """
    A heuristic-based detector for DDoS attacks.

    This detector uses simple statistical methods to identify patterns
    commonly associated with DDoS attacks, such as:
    - Sudden spikes in traffic volume
    - Unusual traffic patterns from individual sources
    - High request rates from single IP addresses
    
    It maintains time-windowed counters to track traffic patterns
    and applies configurable thresholds to detect anomalies.
    """
    def __init__(self, config: dict):
        """
        Initializes the HeuristicDetector with a given configuration.

        Args:
            config (dict): A configuration dictionary. For example:
                           {
                               "window_size": 60,  # in seconds
                               "request_threshold": 100,  # requests per window
                               "ip_threshold": 50,  # requests per IP per window
                               "traffic_spike_factor": 2.0  # factor to detect spikes
                           }
        """
        self.config = config
        self.window_size = config.get("window_size", 60)
        self.request_threshold = config.get("request_threshold", 100)
        self.ip_threshold = config.get("ip_threshold", 50)
        self.traffic_spike_factor = config.get("traffic_spike_factor", 2.0)

        self._request_times = deque(maxlen=1000)
        self._ip_requests = defaultdict(lambda: deque(maxlen=500))
        self._lock = Lock()

    def _cleanup_old_entries(self, current_time: float):
        """
        Removes entries that are older than the window size.

        Args:
            current_time (float): The current time in seconds since epoch.
        """
        cutoff_time = current_time - self.window_size

        # Clean up global request times
        while self._request_times and self._request_times[0] < cutoff_time:
            self._request_times.popleft()

        # Clean up per-IP request times
        for ip, times in list(self._ip_requests.items()):
            while times and times[0] < cutoff_time:
                times.popleft()
            # Remove IPs with no recent requests
            if not times:
                del self._ip_requests[ip]

    def _is_traffic_spike(self, current_time: float) -> bool:
        """
        Detects if there's a significant spike in traffic volume.

        Args:
            current_time (float): The current time in seconds since epoch.

        Returns:
            bool: True if a traffic spike is detected, False otherwise.
        """
        # Calculate current request rate
        current_count = len(self._request_times)
        current_rate = current_count / self.window_size

        # Calculate average rate from previous window
        previous_cutoff = current_time - 2 * self.window_size
        previous_count = sum(1 for t in self._request_times if t <= current_time - self.window_size)
        previous_rate = previous_count / self.window_size if previous_count > 0 else 0

        # Check if current rate is significantly higher than previous rate
        return previous_rate > 0 and current_rate > previous_rate * self.traffic_spike_factor

    def detect(self, ip_address: str) -> dict:
        """
        Analyzes traffic from an IP address and detects potential DDoS attacks.

        Args:
            ip_address (str): The IP address of the request source.

        Returns:
            dict: A dictionary containing detection results. For example:
                  {
                      "is_attack": True,
                      "attack_type": "flood",
                      "details": {
                          "ip_request_count": 120,
                          "total_request_count": 1000,
                          "is_spike": True
                      }
                  }
        """
        current_time = time.time()

        with self._lock:
            # Record the request
            self._request_times.append(current_time)
            self._ip_requests[ip_address].append(current_time)

            # Clean up old entries
            self._cleanup_old_entries(current_time)

            # Get current counts
            total_requests = len(self._request_times)
            ip_requests = len(self._ip_requests[ip_address])

            # Check for attack conditions
            is_attack = False
            attack_type = None
            details = {
                "ip_request_count": ip_requests,
                "total_request_count": total_requests,
                "is_spike": self._is_traffic_spike(current_time)
            }

            # Check if total traffic exceeds threshold
            if total_requests > self.request_threshold:
                is_attack = True
                attack_type = "volume_flood"

            # Check if traffic from a single IP exceeds threshold
            if ip_requests > self.ip_threshold:
                is_attack = True
                attack_type = "targeted_flood"

            # Check for traffic spike
            if details["is_spike"]:
                is_attack = True
                attack_type = "traffic_spike"

            return {
                "is_attack": is_attack,
                "attack_type": attack_type,
                "details": details
            }