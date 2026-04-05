"""
Integration Tests for Streaming Pipeline

Tests for end-to-end streaming flow from collector through Kafka to detection.
"""

import pytest
import time
import json
import threading
import asyncio
from typing import Dict, Any, List
from unittest.mock import Mock, patch, MagicMock
from concurrent.futures import ThreadPoolExecutor

from src.streaming.producer import FlowProducer, ProducerConfig, CompressionType
from src.streaming.consumer import FlowConsumer, ConsumerConfig, AutoOffsetReset
from src.streaming.window_aggregator import WindowAggregator, TimeWindow, RealtimeAggregator

from src.detection.threshold_detector import ThresholdDetector, ThresholdConfig
from src.detection.threshold_detector import AttackType
from src.detection.ensemble import EnsembleDetector, EnsembleConfig, VotingStrategy


class MockKafkaServer:
    """Mock Kafka server for integration testing"""

    def __init__(self):
        self.topics: Dict[str, List[Dict[str, Any]]] = {}
        self.consumer_offsets: Dict[str, int] = {}
        self._lock = threading.Lock()

    def produce(self, topic: str, key: str, value: Dict[str, Any]) -> bool:
        with self._lock:
            if topic not in self.topics:
                self.topics[topic] = []
            self.topics[topic].append({
                'key': key,
                'value': value,
                'timestamp': time.time(),
                'offset': len(self.topics[topic]),
            })
            return True

    def consume(self, topic: str, consumer_group: str, max_records: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            if topic not in self.topics:
                return []
            offset_key = f"{consumer_group}:{topic}"
            if offset_key not in self.consumer_offsets:
                self.consumer_offsets[offset_key] = 0
            current_offset = self.consumer_offsets[offset_key]
            messages = self.topics[topic][current_offset:current_offset + max_records]
            self.consumer_offsets[offset_key] = current_offset + len(messages)
            return messages

    def reset(self):
        with self._lock:
            self.topics.clear()
            self.consumer_offsets.clear()


mock_kafka = MockKafkaServer()


class MockRecord:
    def __init__(self, data):
        self.topic = 'network_flows'
        payload = data['value'] if isinstance(data, dict) and 'value' in data else data
        self.value = payload
        if isinstance(payload, dict):
            self.key = payload.get('flow_id', 'unknown')
        else:
            self.key = data.get('key', 'unknown') if isinstance(data, dict) else 'unknown'
        self.offset = data.get('offset', 0) if isinstance(data, dict) else 0


class MockFuture:
    @property
    def is_done(self) -> bool:
        return True

    def done(self) -> bool:
        return True

    def add_callback(self, callback):
        callback(self)

    def add_errback(self, callback):
        pass


class MockKafkaProducer:
    def __init__(self, **kwargs):
        self.config = kwargs

    def send(self, topic, key=None, value=None):
        mock_kafka.produce(topic, key, value)
        return MockFuture()

    def flush(self):
        pass

    def close(self):
        pass


class MockKafkaConsumer:
    def __init__(self, *topics, **kwargs):
        self.topics = topics
        self.config = kwargs
        self._closed = False

    def poll(self, timeout_ms=1000):
        if self._closed:
            return {}
        messages = {}
        for topic in self.topics:
            records = mock_kafka.consume(topic, self.config.get('group_id', 'test-group'))
            if records:
                # Create a mock TopicPartition object
                from types import SimpleNamespace
                tp = SimpleNamespace(topic=topic, partition=0)
                messages[tp] = [MockRecord(r) for r in records]
        return messages

    def commit(self):
        pass

    def close(self):
        self._closed = True

    def assignment(self):
        return set()

    def end_offsets(self, partitions):
        return {}

    def committed(self, partition):
        return 0


@pytest.fixture(autouse=True)
def patch_kafka():
    with patch('src.streaming.producer.KafkaProducer', MockKafkaProducer):
        with patch('src.streaming.consumer.KafkaConsumer', MockKafkaConsumer):
            yield


class TestStreamingPipeline:

    def setup_method(self):
        mock_kafka.reset()

        self.producer_config = ProducerConfig(
            bootstrap_servers="localhost:9092",
            topic_flows="network_flows",
            acks=1,
        )
        self.consumer_config = ConsumerConfig(
            bootstrap_servers="localhost:9092",
            group_id="test-detection-group",
            topics_flows=["network_flows"],
            auto_offset_reset=AutoOffsetReset.EARLIEST,
            enable_auto_commit=True,
        )

    def test_producer_consumer_flow(self):
        producer = FlowProducer(self.producer_config)
        producer.start()

        test_flows = [
            {
                'flow_id': f'flow_{i}',
                'ip_src': f'192.168.1.{i}',
                'ip_dst': '10.0.0.1',
                'protocol': 6,
                'sport': 12345 + i,
                'dport': 80,
                'total_packets': 100,
                'total_bytes': 10000,
            }
            for i in range(10)
        ]

        for flow in test_flows:
            producer.send_flow(flow)

        producer.flush()

        consumer = FlowConsumer(self.consumer_config)
        consumer.start()

        received_flows = []

        def callback(flow):
            received_flows.append(flow)

        consumer.register_flow_callback(callback)

        # Poll for messages
        for _ in range(5):
            messages = consumer.consumer.poll(timeout_ms=1000)
            if messages:
                for tp, records in messages.items():
                    for record in records:
                        callback(record.value)
            time.sleep(0.1)

        consumer.stop()
        producer.stop()

        assert len(received_flows) == 10
        assert received_flows[0]['flow_id'] == 'flow_0'

    def test_producer_batch_send(self):
        producer = FlowProducer(self.producer_config)
        producer.start()

        test_flows = [
            {
                'flow_id': f'batch_flow_{i}',
                'ip_src': '192.168.1.1',
                'ip_dst': '10.0.0.1',
                'protocol': 6,
                'sport': 10000 + i,
                'dport': 443,
                'total_packets': 50,
                'total_bytes': 5000,
            }
            for i in range(100)
        ]

        asyncio.run(producer.send_batch(test_flows, batch_size=20))
        producer.flush()

        assert mock_kafka.topics.get('network_flows') is not None
        assert len(mock_kafka.topics.get('network_flows', [])) == 100

        producer.stop()

    def test_end_to_end_detection_pipeline(self):
        producer = FlowProducer(self.producer_config)
        aggregator = WindowAggregator(window_sizes=[1, 5])
        threshold_detector = ThresholdDetector(ThresholdConfig(
            packets_per_second_threshold=1000,
            enable_dynamic_thresholds=False,
        ))

        detection_results = []

        def process_flow(flow_dict):
            aggregated = aggregator.add_flow(flow_dict)
            if aggregated:
                features_dict = aggregated.get('metrics', {})
                from src.detection.feature_extractor import TrafficFeatures
                tf = TrafficFeatures(
                    timestamp=time.time(),
                    window_size=5,
                    packets_per_second=features_dict.get('packets_per_second', 0),
                    total_packets=features_dict.get('total_packets', 0),
                    entropy_src_ip=features_dict.get('entropy_src_ip', 0),
                )
                alerts = threshold_detector.detect(tf)
                if alerts:
                    detection_results.extend(alerts)

        producer.start()

        attack_start = time.time()
        flow_id = 0

        while time.time() - attack_start < 3:
            for src_ip_suffix in range(100):
                flow = {
                    'flow_id': f'attack_flow_{flow_id}',
                    'ip_src': f'192.168.{src_ip_suffix % 256}.{src_ip_suffix}',
                    'ip_dst': '10.0.0.1',
                    'protocol': 6,
                    'sport': 12345,
                    'dport': 80,
                    'total_packets': 10,
                    'total_bytes': 600,
                    'tcp_syn_count': 1,
                    'tcp_syn_ack_count': 0,
                }
                process_flow(flow)
                flow_id += 1
            time.sleep(0.01)

        producer.stop()

        assert len(detection_results) > 0

    def test_window_aggregator_integration(self):
        aggregator = RealtimeAggregator(window_size_seconds=1)

        flows_sent = 0
        start_time = time.time()
        completed = None

        while time.time() - start_time < 2:
            flow = {
                'flow_id': f'test_flow_{flows_sent}',
                'ip_src': f'192.168.1.{flows_sent % 10}',
                'ip_dst': '10.0.0.1',
                'protocol': 6,
                'sport': 10000 + flows_sent,
                'dport': 80,
                'total_packets': 5,
                'total_bytes': 500,
            }

            completed = aggregator.add_flow(flow)
            flows_sent += 1

            if completed:
                break

            time.sleep(0.01)

        assert aggregator.get_packet_rate() >= 0

        if completed:
            assert len(aggregator.completed_windows) > 0
            assert completed.packets_per_second >= 0

    def test_consumer_with_multiple_producers(self):
        producer1 = FlowProducer(self.producer_config)
        producer2 = FlowProducer(self.producer_config)

        producer1.start()
        producer2.start()

        for i in range(50):
            producer1.send_flow({
                'flow_id': f'producer1_flow_{i}',
                'ip_src': '192.168.1.1',
                'ip_dst': '10.0.0.1',
                'protocol': 6,
                'sport': 10000 + i,
                'dport': 80,
                'total_packets': 10,
            }, key=f"partition_key_{i % 3}")

            producer2.send_flow({
                'flow_id': f'producer2_flow_{i}',
                'ip_src': '192.168.1.2',
                'ip_dst': '10.0.0.2',
                'protocol': 17,
                'sport': 20000 + i,
                'dport': 53,
                'total_packets': 5,
            }, key=f"partition_key_{i % 3}")

        producer1.flush()
        producer2.flush()

        consumer = FlowConsumer(self.consumer_config)
        consumer.start()

        received = []

        def callback(flow):
            received.append(flow)

        consumer.register_flow_callback(callback)

        start = time.time()
        while len(received) < 100 and time.time() - start < 10:
            messages = consumer.consumer.poll(timeout_ms=500)
            if messages:
                for tp, records in messages.items():
                    for record in records:
                        callback(record.value)
            time.sleep(0.1)

        consumer.stop()
        producer1.stop()
        producer2.stop()

        assert len(received) == 100
        assert any('producer1_flow' in r['flow_id'] for r in received)
        assert any('producer2_flow' in r['flow_id'] for r in received)

    def test_pipeline_error_handling(self):
        producer = FlowProducer(self.producer_config)
        producer.start()

        malformed_flow = {'flow_id': 'bad_flow'}
        result = producer.send_flow(malformed_flow)
        assert result is True

        valid_flow = {
            'flow_id': 'good_flow',
            'ip_src': '192.168.1.1',
            'ip_dst': '10.0.0.1',
            'protocol': 6,
            'sport': 12345,
            'dport': 80,
            'total_packets': 100,
        }

        result = producer.send_flow(valid_flow)
        assert result is True

        producer.flush()
        producer.stop()

        topic_messages = mock_kafka.topics.get('network_flows', [])
        assert any(msg['value'].get('flow_id') == 'good_flow' for msg in topic_messages)


class TestPerformanceMetrics:

    def setup_method(self):
        mock_kafka.reset()
        self.producer_config = ProducerConfig(
            bootstrap_servers="localhost:9092",
            topic_flows="network_flows",
            acks=1,
        )

    def test_high_throughput_producer(self):
        producer = FlowProducer(self.producer_config)
        producer.start()

        start_time = time.time()
        message_count = 1000

        for i in range(message_count):
            producer.send_flow({
                'flow_id': f'perf_flow_{i}',
                'ip_src': f'192.168.1.{i % 256}',
                'ip_dst': '10.0.0.1',
                'protocol': 6,
                'sport': 10000 + (i % 65535),
                'dport': 80,
                'total_packets': 10,
                'total_bytes': 1000,
            })

        producer.flush()
        elapsed = time.time() - start_time
        producer.stop()

        throughput = message_count / elapsed if elapsed > 0 else 0
        print(f"Throughput: {throughput:.0f} messages/sec")

        assert throughput > 100
        assert len(mock_kafka.topics.get('network_flows', [])) >= message_count

    def test_pipeline_latency(self):
        producer = FlowProducer(self.producer_config)
        aggregator = RealtimeAggregator(window_size_seconds=1)

        producer.start()

        latencies = []

        for i in range(100):
            send_time = time.time()

            flow = {
                'flow_id': f'latency_test_{i}',
                'ip_src': '192.168.1.1',
                'ip_dst': '10.0.0.1',
                'protocol': 6,
                'sport': 10000 + i,
                'dport': 80,
                'total_packets': 1,
                'total_bytes': 100,
            }

            aggregator.add_flow(flow)
            latencies.append(time.time() - send_time)
            time.sleep(0.001)

        producer.stop()

        avg_latency = sum(latencies) / len(latencies) * 1000
        p99_latency = sorted(latencies)[-1] * 1000

        print(f"Average latency: {avg_latency:.2f} ms")
        print(f"P99 latency: {p99_latency:.2f} ms")

        assert avg_latency < 100.0


def run_integration_tests():
    pytest.main([__file__, '-v', '--tb=short'])


if __name__ == '__main__':
    run_integration_tests()