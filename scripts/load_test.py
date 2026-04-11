#!/usr/bin/env python3
"""
Load Testing Script for DDoS Detection System

Simulates various attack patterns to test system performance:
- SYN Flood
- UDP Flood
- HTTP Flood
- Mixed Attack
"""

import argparse
import asyncio
import json
import random
import statistics
import sys
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional
import aiohttp
import numpy as np

try:
    from kafka import KafkaProducer
    from kafka.errors import KafkaError
except ImportError:
    print("kafka-python not installed. Install with: pip install kafka-python")
    sys.exit(1)


@dataclass
class LoadTestConfig:
    target_url: str = "http://localhost:8000"
    kafka_bootstrap: str = "localhost:9092"
    attack_type: str = "mixed"
    attack_rate: int = 1000
    duration: int = 60
    num_workers: int = 10
    payload_size: int = 1024
    use_kafka: bool = True
    report_interval: int = 10


@dataclass
class TestStats:
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    response_times: List[float] = field(default_factory=list)
    errors: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    start_time: float = 0
    end_time: float = 0
    
    def add_response(self, success: bool, response_time: float, error: str = None):
        self.total_requests += 1
        if success:
            self.successful_requests += 1
        else:
            self.failed_requests += 1
            if error:
                self.errors[error] += 1
        self.response_times.append(response_time)
    
    def get_stats(self) -> Dict:
        if not self.response_times:
            return {}
        
        elapsed = self.end_time - self.start_time
        return {
            'total_requests': self.total_requests,
            'successful': self.successful_requests,
            'failed': self.failed_requests,
            'rps': self.total_requests / elapsed if elapsed > 0 else 0,
            'avg_response_time': statistics.mean(self.response_times),
            'p50_response_time': statistics.median(self.response_times),
            'p95_response_time': np.percentile(self.response_times, 95),
            'p99_response_time': np.percentile(self.response_times, 99),
            'min_response_time': min(self.response_times),
            'max_response_time': max(self.response_times),
            'errors': dict(self.errors),
        }


class DDoSLoadGenerator:
    def __init__(self, config: LoadTestConfig):
        self.config = config
        self.stats = TestStats()
        self.producer: Optional[KafkaProducer] = None
        self.running = False
        
    def _create_syn_flood_payload(self) -> Dict:
        return {
            'flow_id': str(uuid.uuid4()),
            'ip_src': f"10.0.{random.randint(0,255)}.{random.randint(1,254)}",
            'ip_dst': f"192.168.{random.randint(0,255)}.{random.randint(1,254)}",
            'protocol': 6,
            'sport': random.randint(1024, 65535),
            'dport': 80,
            'tcp_flags': 0x02,  # SYN
            'packets': random.randint(10, 100),
            'bytes': random.randint(500, 5000),
        }
    
    def _create_udp_flood_payload(self) -> Dict:
        return {
            'flow_id': str(uuid.uuid4()),
            'ip_src': f"10.0.{random.randint(0,255)}.{random.randint(1,254)}",
            'ip_dst': f"192.168.{random.randint(0,255)}.{random.randint(1,254)}",
            'protocol': 17,
            'sport': random.randint(1024, 65535),
            'dport': 53,
            'packets': random.randint(100, 1000),
            'bytes': random.randint(10000, 100000),
        }
    
    def _create_http_flood_payload(self) -> Dict:
        return {
            'flow_id': str(uuid.uuid4()),
            'ip_src': f"10.0.{random.randint(0,255)}.{random.randint(1,254)}",
            'ip_dst': f"192.168.{random.randint(0,255)}.{random.randint(1,254)}",
            'protocol': 6,
            'sport': random.randint(1024, 65535),
            'dport': 80,
            'http_method': random.choice(['GET', 'POST']),
            'http_path': random.choice(['/', '/api', '/login', '/search']),
            'packets': random.randint(5, 20),
            'bytes': random.randint(200, 2000),
        }
    
    def _create_mixed_payload(self) -> Dict:
        attack_types = ['syn', 'udp', 'http']
        attack = random.choice(attack_types)
        
        if attack == 'syn':
            return self._create_syn_flood_payload()
        elif attack == 'udp':
            return self._create_udp_flood_payload()
        else:
            return self._create_http_flood_payload()
    
    def _get_payload(self) -> Dict:
        attack_type = self.config.attack_type.lower()
        
        if attack_type == 'syn_flood' or attack_type == 'syn':
            return self._create_syn_flood_payload()
        elif attack_type == 'udp_flood' or attack_type == 'udp':
            return self._create_udp_flood_payload()
        elif attack_type == 'http_flood' or attack_type == 'http':
            return self._create_http_flood_payload()
        else:
            return self._create_mixed_payload()
    
    async def _send_via_api(self, session: aiohttp.ClientSession):
        payload = self._get_payload()
        
        try:
            start = time.time()
            async with session.post(
                f"{self.config.target_url}/flows/query",
                json=payload,
                timeout=aiohttp.ClientTimeout(total=5)
            ) as resp:
                response_time = time.time() - start
                if resp.status < 400:
                    self.stats.add_response(True, response_time)
                else:
                    self.stats.add_response(False, response_time, f"HTTP_{resp.status}")
        except asyncio.TimeoutError:
            self.stats.add_response(False, 5.0, "timeout")
        except Exception as e:
            self.stats.add_response(False, 0, str(type(e).__name__))
    
    def _send_via_kafka(self, payload: Dict):
        if not self.producer:
            return
        try:
            self.producer.send(
                'network_flows',
                value=payload,
                key=payload.get('flow_id', '').encode()
            )
            self.stats.add_response(True, 0)
        except Exception as e:
            self.stats.add_response(False, 0, str(type(e).__name__))
    
    async def _worker(self, worker_id: int, session: aiohttp.ClientSession):
        interval = 1.0 / (self.config.attack_rate / self.config.num_workers)
        
        while self.running:
            if self.config.use_kafka:
                self._send_via_kafka(self._get_payload())
            else:
                await self._send_via_api(session)
            
            await asyncio.sleep(max(0.001, interval))
    
    async def _report_progress(self):
        while self.running:
            await asyncio.sleep(self.config.report_interval)
            stats = self.stats.get_stats()
            print(f"\n[{time.strftime('%H:%M:%S')}] Progress Report:")
            print(f"  Total Requests: {stats.get('total_requests', 0)}")
            print(f"  RPS: {stats.get('rps', 0):.2f}")
            print(f"  Success Rate: {stats.get('successful', 0) / max(1, stats.get('total_requests', 1)) * 100:.1f}%")
            if stats.get('avg_response_time'):
                print(f"  Avg Response: {stats.get('avg_response_time', 0)*1000:.2f}ms")
    
    def _init_kafka(self):
        if self.config.use_kafka:
            try:
                self.producer = KafkaProducer(
                    bootstrap_servers=self.config.kafka_bootstrap,
                    value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                    acks=0,
                    batch_size=16384,
                    linger_ms=5,
                )
                print(f"Kafka producer connected to {self.config.kafka_bootstrap}")
            except Exception as e:
                print(f"Warning: Kafka connection failed: {e}")
                print("Falling back to HTTP mode")
                self.config.use_kafka = False
    
    async def run(self):
        self.running = True
        self.stats.start_time = time.time()
        
        self._init_kafka()
        
        async with aiohttp.ClientSession() as session:
            tasks = [
                asyncio.create_task(self._worker(i, session))
                for i in range(self.config.num_workers)
            ]
            tasks.append(asyncio.create_task(self._report_progress()))
            
            try:
                await asyncio.sleep(self.config.duration)
            finally:
                self.running = False
                for task in tasks:
                    task.cancel()
                
                # Wait for cancellation
                await asyncio.gather(*tasks, return_exceptions=True)
        
        self.stats.end_time = time.time()
        
        # Print final report
        self._print_final_report()
        
        if self.producer:
            self.producer.flush()
            self.producer.close()
    
    def _print_final_report(self):
        stats = self.stats.get_stats()
        
        print("\n" + "="*60)
        print("FINAL TEST REPORT")
        print("="*60)
        print(f"Attack Type:     {self.config.attack_type}")
        print(f"Target:         {self.config.target_url}")
        print(f"Duration:       {self.config.duration}s")
        print(f"Workers:        {self.config.num_workers}")
        print(f"Attack Rate:    {self.config.attack_rate} rps")
        print("-"*60)
        print(f"Total Requests: {stats['total_requests']:,}")
        print(f"Successful:     {stats['successful']:,}")
        print(f"Failed:         {stats['failed']:,}")
        print(f"RPS:            {stats['rps']:.2f}")
        print("-"*60)
        print("Response Times:")
        print(f"  Min:    {stats['min_response_time']*1000:.2f}ms")
        print(f"  Avg:    {stats['avg_response_time']*1000:.2f}ms")
        print(f"  P50:    {stats['p50_response_time']*1000:.2f}ms")
        print(f"  P95:    {stats['p95_response_time']*1000:.2f}ms")
        print(f"  P99:    {stats['p99_response_time']*1000:.2f}ms")
        print(f"  Max:    {stats['max_response_time']*1000:.2f}ms")
        
        if stats.get('errors'):
            print("-"*60)
            print("Errors:")
            for error, count in stats['errors'].items():
                print(f"  {error}: {count}")
        
        print("="*60)


def main():
    parser = argparse.ArgumentParser(description="DDoS System Load Tester")
    parser.add_argument('--target-url', default='http://localhost:8000',
                        help='Target API URL')
    parser.add_argument('--kafka-bootstrap', default='localhost:9092',
                        help='Kafka bootstrap servers')
    parser.add_argument('--attack-type', default='mixed',
                        choices=['mixed', 'syn', 'syn_flood', 'udp', 'udp_flood', 
                                'http', 'http_flood'],
                        help='Type of attack to simulate')
    parser.add_argument('--attack-rate', type=int, default=1000,
                        help='Requests per second')
    parser.add_argument('--duration', type=int, default=60,
                        help='Test duration in seconds')
    parser.add_argument('--workers', type=int, default=10,
                        help='Number of concurrent workers')
    parser.add_argument('--http', action='store_true',
                        help='Use HTTP instead of Kafka')
    parser.add_argument('--report-interval', type=int, default=10,
                        help='Report interval in seconds')
    
    args = parser.parse_args()
    
    config = LoadTestConfig(
        target_url=args.target_url,
        kafka_bootstrap=args.kafka_bootstrap,
        attack_type=args.attack_type,
        attack_rate=args.attack_rate,
        duration=args.duration,
        num_workers=args.workers,
        use_kafka=not args.http,
        report_interval=args.report_interval,
    )
    
    generator = DDoSLoadGenerator(config)
    asyncio.run(generator.run())


if __name__ == "__main__":
    main()
