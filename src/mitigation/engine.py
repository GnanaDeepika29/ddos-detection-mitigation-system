"""
The core mitigation engine that applies various strategies to incoming traffic.
"""

from .rate_limiter import RateLimiter, RateLimiterConfig

class MitigationEngine:
    """
    Orchestrates various DDoS mitigation strategies.

    This engine is designed to be the central point for applying mitigation
    techniques. It can be configured with different strategies, such as rate
    limiting, and can be easily extended to include more advanced methods like
    IP blacklisting or challenge-response tests.
    """
    def __init__(self, config: dict):
        """
        Initializes the MitigationEngine with a given configuration.

        The configuration dictionary specifies which mitigation strategies to enable
        and their respective parameters.

        Args:
            config (dict): A configuration dictionary. For example:
                           {
                               "rate_limiting": {
                                   "enabled": True,
                                   "capacity": 10,
                                   "refill_rate": 5
                               }
                           }
        """
        self.config = config
        self.rate_limiter = None

        if self.config.get("rate_limiting", {}).get("enabled"):
            rate_limiter_config = self.config["rate_limiting"]
            config = RateLimiterConfig(
                default_packet_rate=rate_limiter_config.get("refill_rate", 1000),
                default_burst_multiplier=rate_limiter_config.get("capacity", 10) / rate_limiter_config.get("refill_rate", 1000),
            )
            self.rate_limiter = RateLimiter(config)

    def process_request(self, identifier: str) -> bool:
        """
        Processes a request and decides whether to allow or block it.

        This method checks the request against all enabled mitigation strategies.
        If any strategy decides to block the request, it is blocked.

        Args:
            identifier (str): A unique identifier for the request source (e.g., IP address).

        Returns:
            bool: True if the request is allowed, False if it should be blocked.
        """
        if self.rate_limiter:
            allowed = self.rate_limiter.check_rate_limit(
                identifier,
                packets=1,
                protocol=6,
            )
            if not allowed:
                print(f"Request from {identifier} blocked by rate limiter.")
                return False

        # Future mitigation strategies can be checked here.
        # For example:
        # if self.ip_blacklist and self.ip_blacklist.is_blocked(identifier):
        #     print(f"Request from {identifier} blocked by IP blacklist.")
        #     return False

        return True