"""
Generates and simulates network traffic for testing purposes.
"""

import random
import time
from concurrent.futures import ThreadPoolExecutor

class TrafficCollector:
    """
    Simulates network traffic for testing DDoS detection and mitigation.

    This collector generates synthetic traffic data that can be used to test
    the detection and mitigation systems. It can simulate both normal traffic
    and various types of DDoS attacks.
    """
    def __init__(self, config: dict):
        """
        Initializes the TrafficCollector with a given configuration.

        Args:
            config (dict): A configuration dictionary. For example:
                           {
                               "normal_traffic_rate": 10,  # requests per second
                               "attack_traffic_rate": 100,  # requests per second
                               "attack_duration": 60,  # seconds
                               "normal_ips": 10,  # number of unique normal IPs
                               "attack_ips": 5,  # number of unique attack IPs
                               "targets": ["192.168.1.100", "192.168.1.101"]  # target IPs
                           }
        """
        self.config = config
        self.normal_traffic_rate = config.get("normal_traffic_rate", 10)
        self.attack_traffic_rate = config.get("attack_traffic_rate", 100)
        self.attack_duration = config.get("attack_duration", 60)
        self.normal_ips = config.get("normal_ips", 10)
        self.attack_ips = config.get("attack_ips", 5)
        self.targets = config.get("targets", ["192.168.1.100"])

        # Generate synthetic IP addresses
        self._normal_ip_pool = self._generate_ip_pool(self.normal_ips)
        self._attack_ip_pool = self._generate_ip_pool(self.attack_ips)

    def _generate_ip_pool(self, count: int) -> list:
        """
        Generates a pool of synthetic IP addresses.

        Args:
            count (int): The number of IP addresses to generate.

        Returns:
            list: A list of synthetic IP addresses.
        """
        ip_pool = []
        for i in range(count):
            ip = f"192.168.1.{100 + i}"
            ip_pool.append(ip)
        return ip_pool

    def _simulate_normal_traffic(self, callback, duration: int):
        """
        Simulates normal traffic.

        Args:
            callback (callable): A function to call for each simulated request.
            duration (int): The duration to simulate traffic for, in seconds.
        """
        start_time = time.time()
        while time.time() - start_time < duration:
            # Choose a random source IP from the normal pool
            source_ip = random.choice(self._normal_ip_pool)
            # Choose a random target IP
            target_ip = random.choice(self.targets)
            # Call the callback with the simulated request
            callback(source_ip, target_ip)
            # Wait for a short time based on the traffic rate
            time.sleep(1 / self.normal_traffic_rate)

    def _simulate_attack_traffic(self, callback, duration: int):
        """
        Simulates attack traffic.

        Args:
            callback (callable): A function to call for each simulated request.
            duration (int): The duration to simulate traffic for, in seconds.
        """
        start_time = time.time()
        while time.time() - start_time < duration:
            # Choose a random source IP from the attack pool
            source_ip = random.choice(self._attack_ip_pool)
            # Choose a random target IP
            target_ip = random.choice(self.targets)
            # Call the callback with the simulated request
            callback(source_ip, target_ip)
            # Wait for a short time based on the attack traffic rate
            time.sleep(1 / self.attack_traffic_rate)

    def start_simulation(self, callback, duration: int = 300):
        """
        Starts a traffic simulation.

        This method simulates a mix of normal traffic and a DDoS attack.

        Args:
            callback (callable): A function to call for each simulated request.
                The function should accept two arguments: source_ip and target_ip.
            duration (int): The total duration of the simulation, in seconds.
        """
        print(f"Starting traffic simulation for {duration} seconds...")
        print(f"Normal traffic rate: {self.normal_traffic_rate} requests/second")
        print(f"Attack traffic rate: {self.attack_traffic_rate} requests/second")
        print(f"Attack duration: {self.attack_duration} seconds")

        # Start normal traffic in a separate thread
        with ThreadPoolExecutor(max_workers=2) as executor:
            # Start normal traffic
            normal_future = executor.submit(self._simulate_normal_traffic, callback, duration)

            # Wait a bit, then start attack traffic
            time.sleep(30)  # Start attack after 30 seconds
            print("Starting DDoS attack simulation...")
            attack_future = executor.submit(self._simulate_attack_traffic, callback, self.attack_duration)

            # Wait for both simulations to complete
            normal_future.result()
            attack_future.result()

        print("Traffic simulation completed.")