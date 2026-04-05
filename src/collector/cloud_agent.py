"""
Cloud Flow Log Agent

Collects flow logs from cloud providers (AWS VPC Flow Logs, GCP Flow Logs, Azure NSG Flow Logs).
Provides a unified interface for cloud-native traffic collection.
"""

import json
import asyncio
import logging
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, Callable
from datetime import datetime

logger = logging.getLogger(__name__)


class CloudProvider(Enum):
    """Supported cloud providers"""
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    LOCAL = "local"


class FlowLogSource(Enum):
    """Types of flow log sources"""
    VPC_FLOW_LOGS = "vpc_flow_logs"
    NSG_FLOW_LOGS = "nsg_flow_logs"
    SUBNET_FLOW_LOGS = "subnet_flow_logs"
    ENI_FLOW_LOGS = "eni_flow_logs"
    LOAD_BALANCER_LOGS = "load_balancer_logs"


@dataclass
class CloudFlowLogConfig:
    """Configuration for cloud flow log collection"""
    provider: CloudProvider = CloudProvider.LOCAL
    region: str = "us-east-1"

    # AWS specific
    aws_vpc_ids: List[str] = field(default_factory=list)
    aws_subnet_ids: List[str] = field(default_factory=list)
    aws_log_group_names: List[str] = field(default_factory=list)
    aws_kinesis_stream: Optional[str] = None

    # Azure specific
    azure_subscription_id: Optional[str] = None
    azure_resource_group: Optional[str] = None
    azure_network_watcher: Optional[str] = None
    azure_storage_account: Optional[str] = None

    # GCP specific
    gcp_project_id: Optional[str] = None
    gcp_subscription_name: Optional[str] = None
    gcp_topic_name: Optional[str] = None

    # Common settings
    poll_interval_seconds: int = 10
    batch_size: int = 100
    max_queue_size: int = 10000
    include_metadata: bool = True


class CloudFlowLogAgent:
    """
    Unified agent for collecting flow logs from cloud providers.
    Supports AWS VPC Flow Logs, Azure NSG Flow Logs, and GCP Flow Logs.
    """

    def __init__(self, config: CloudFlowLogConfig, flow_handler: Optional[Callable] = None):
        self.config = config
        self.flow_handler = flow_handler
        self.is_running = False

        self.flow_queue: Optional[asyncio.Queue] = None
        self._poll_task: Optional[asyncio.Task] = None

        self._aws_client = None
        self._azure_client = None
        self._gcp_client = None

        self._aws_stream_tokens: Dict[str, str] = {}

        self.stats = {
            'flows_processed': 0,
            'flows_dropped': 0,
            'api_errors': 0,
            'last_successful_poll': None,
        }

        logger.info(f"CloudFlowLogAgent initialized for provider: {config.provider.value}")

    def _get_aws_client(self):
        """Lazy-load AWS client"""
        if self._aws_client is None:
            try:
                import boto3
                self._aws_client = boto3.client('logs', region_name=self.config.region)
                logger.info("AWS CloudWatch Logs client initialized")
            except ImportError:
                logger.error("boto3 not installed. Install with: pip install boto3")
                raise
            except Exception as e:
                logger.error(f"Failed to initialize AWS client: {e}")
                raise
        return self._aws_client

    def _get_azure_client(self):
        """Lazy-load Azure client"""
        if self._azure_client is None:
            try:
                from azure.mgmt.network import NetworkManagementClient
                from azure.identity import DefaultAzureCredential

                credential = DefaultAzureCredential()
                self._azure_client = NetworkManagementClient(
                    credential=credential,
                    subscription_id=self.config.azure_subscription_id,
                )
                logger.info("Azure Network client initialized")
            except ImportError:
                logger.error("Azure SDK not installed. Install with: pip install azure-mgmt-network azure-identity")
                raise
            except Exception as e:
                logger.error(f"Failed to initialize Azure client: {e}")
                raise
        return self._azure_client

    def _get_gcp_client(self):
        """Lazy-load GCP client"""
        if self._gcp_client is None:
            try:
                from google.cloud import logging as gcp_logging
                self._gcp_client = gcp_logging.Client(project=self.config.gcp_project_id)
                logger.info("GCP Logging client initialized")
            except ImportError:
                logger.error("Google Cloud SDK not installed. Install with: pip install google-cloud-logging")
                raise
            except Exception as e:
                logger.error(f"Failed to initialize GCP client: {e}")
                raise
        return self._gcp_client

    async def _poll_aws_flow_logs(self):
        """Poll AWS VPC Flow Logs from CloudWatch Logs"""
        client = self._get_aws_client()

        for log_group in self.config.aws_log_group_names:
            try:
                streams_response = client.describe_log_streams(
                    logGroupName=log_group,
                    orderBy='LastEventTime',
                    descending=True,
                    limit=10,
                )

                for stream in streams_response.get('logStreams', []):
                    stream_name = stream['logStreamName']
                    stream_key = f"{log_group}/{stream_name}"

                    kwargs = {
                        'logGroupName': log_group,
                        'logStreamName': stream_name,
                        'startFromHead': False,
                        'limit': self.config.batch_size,
                    }
                    if stream_key in self._aws_stream_tokens:
                        kwargs['nextToken'] = self._aws_stream_tokens[stream_key]

                    events_response = client.get_log_events(**kwargs)

                    # Persist the forward token for the next poll cycle
                    next_token = events_response.get('nextForwardToken')
                    if next_token:
                        self._aws_stream_tokens[stream_key] = next_token

                    for event in events_response.get('events', []):
                        flow = self._parse_aws_flow_log(event['message'], event['timestamp'])
                        if flow:
                            await self.flow_queue.put(flow)
                            self.stats['flows_processed'] += 1

            except Exception as e:
                logger.error(f"Error polling AWS flow logs from {log_group}: {e}")
                self.stats['api_errors'] += 1

    def _parse_aws_flow_log(self, log_message: str, timestamp: int) -> Optional[Dict[str, Any]]:
        """
        Parse AWS VPC Flow Log entry.
        Format: version account-id interface-id srcaddr dstaddr srcport dstport
                protocol packets bytes start end action log-status
        """
        try:
            fields = log_message.strip().split()
            if len(fields) < 14:
                return None

            return {
                'timestamp': timestamp / 1000.0,  # Convert ms to seconds
                'source': 'aws_vpc_flow_logs',
                'ip_src': fields[3],
                'ip_dst': fields[4],
                'sport': int(fields[5]),
                'dport': int(fields[6]),
                'protocol': int(fields[7]),
                'packets': int(fields[8]),
                'bytes': int(fields[9]),
                'action': fields[12],
                'log_status': fields[13],
                'interface_id': fields[2],
                'account_id': fields[1],
                'flow_direction': 'forward',
            }
        except Exception as e:
            logger.debug(f"Failed to parse AWS flow log: {e}")
            return None

    async def _poll_azure_flow_logs(self):
        """Poll Azure NSG Flow Logs"""
        client = self._get_azure_client()

        try:
            logger.info("Polling Azure NSG flow logs (implementation depends on storage account access)")
            # Production implementation: read from Azure Storage blobs or
            # Event Hubs for real-time flow logs.
            await asyncio.sleep(self.config.poll_interval_seconds)

        except Exception as e:
            logger.error(f"Error polling Azure flow logs: {e}")
            self.stats['api_errors'] += 1

    def _parse_azure_flow_log(self, log_entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse Azure NSG Flow Log entry"""
        try:
            raw_ts = log_entry.get('time') or log_entry.get('timestamp')
            if isinstance(raw_ts, str):
                ts = datetime.fromisoformat(raw_ts.rstrip('Z')).timestamp()
            elif isinstance(raw_ts, (int, float)):
                ts = float(raw_ts)
            else:
                ts = datetime.utcnow().timestamp()

            protocol_str = log_entry.get('protocol', 'TCP').upper()
            protocol_num = 6 if protocol_str == 'TCP' else (17 if protocol_str == 'UDP' else 1)

            flow = {
                'timestamp': ts,
                'source': 'azure_nsg_flow_logs',
                'ip_src': log_entry.get('srcIP'),
                'ip_dst': log_entry.get('dstIP'),
                'sport': log_entry.get('srcPort'),
                'dport': log_entry.get('dstPort'),
                'protocol': protocol_num,
                'packets': log_entry.get('packetsSent', 0),
                'bytes': log_entry.get('bytesSent', 0),
                'action': log_entry.get('flowStatus', 'ALLOWED'),
            }
            return flow if all([flow['ip_src'], flow['ip_dst']]) else None
        except Exception as e:
            logger.debug(f"Failed to parse Azure flow log: {e}")
            return None

    async def _poll_gcp_flow_logs(self):
        """Poll GCP VPC Flow Logs"""
        client = self._get_gcp_client()

        try:
            filter_str = 'logName:"flows" AND severity>=INFO'

            for entry in client.list_entries(filter_=filter_str, max_results=self.config.batch_size):
                flow = self._parse_gcp_flow_log(entry)
                if flow:
                    await self.flow_queue.put(flow)
                    self.stats['flows_processed'] += 1

        except Exception as e:
            logger.error(f"Error polling GCP flow logs: {e}")
            self.stats['api_errors'] += 1

    def _parse_gcp_flow_log(self, log_entry) -> Optional[Dict[str, Any]]:
        """Parse GCP VPC Flow Log entry"""
        try:
            payload = log_entry.payload
            if 'connection' not in payload:
                return None

            conn = payload['connection']

            protocol = int(conn.get('protocol', 17))

            disposition = payload.get('disposition', 'ALLOWED').upper()
            action = 'ALLOWED' if disposition != 'DENIED' else 'DENIED'

            return {
                'timestamp': log_entry.timestamp.timestamp(),
                'source': 'gcp_vpc_flow_logs',
                'ip_src': conn.get('src_ip'),
                'ip_dst': conn.get('dest_ip'),
                'sport': int(conn.get('src_port', 0)),
                'dport': int(conn.get('dest_port', 0)),
                'protocol': protocol,
                'packets': payload.get('packets_sent', 0),   
                'bytes': payload.get('bytes_sent', 0),       
                'action': action,
            }
        except Exception as e:
            logger.debug(f"Failed to parse GCP flow log: {e}")
            return None

    async def _poll_loop(self):
        """Main polling loop for cloud flow logs"""
        logger.info(f"Starting cloud flow log collection for {self.config.provider.value}")

        while self.is_running:
            try:
                if self.config.provider == CloudProvider.AWS:
                    await self._poll_aws_flow_logs()
                elif self.config.provider == CloudProvider.AZURE:
                    await self._poll_azure_flow_logs()
                elif self.config.provider == CloudProvider.GCP:
                    await self._poll_gcp_flow_logs()
                else:
                    logger.warning(f"Unsupported provider: {self.config.provider}")
                    break

                self.stats['last_successful_poll'] = datetime.now()
                await asyncio.sleep(self.config.poll_interval_seconds)

            except Exception as e:
                logger.error(f"Error in cloud flow log polling loop: {e}")
                await asyncio.sleep(5)  # Back off on error

    async def start(self):
        """Start flow log collection"""
        self.flow_queue = asyncio.Queue(maxsize=self.config.max_queue_size)
        self.is_running = True

        self._poll_task = asyncio.create_task(self._poll_loop())

    def stop(self):
        """Stop flow log collection"""
        logger.info("Stopping cloud flow log collection")
        self.is_running = False
        if self._poll_task:
            self._poll_task.cancel()

    async def get_flow(self, timeout: Optional[float] = None) -> Optional[Dict[str, Any]]:
        """Get next flow from the queue"""
        if self.flow_queue is None:
            return None
            
        try:
            return await asyncio.wait_for(self.flow_queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None

    def get_stats(self) -> Dict[str, Any]:
        """Get collection statistics"""
        return {
            **self.stats,
            'queue_size': self.flow_queue.qsize() if self.flow_queue else 0,
            'is_running': self.is_running,
            'provider': self.config.provider.value,
        }

    async def run_pipeline(self, flow_builder):
        """Run the complete pipeline with flow builder"""
        await self.start()

        try:
            while self.is_running:
                flow_dict = await self.get_flow(timeout=1.0)
                if flow_dict and flow_builder:
                    # Convert cloud flow to packet format for flow builder
                    packet_format = {
                        'ip_src': flow_dict['ip_src'],
                        'ip_dst': flow_dict['ip_dst'],
                        'sport': flow_dict['sport'],
                        'dport': flow_dict['dport'],
                        'protocol': flow_dict['protocol'],
                        'length': flow_dict.get('bytes', 0),
                        'timestamp': flow_dict.get('timestamp', 0),
                    }
                    flow_builder.process_packet(packet_format)
        finally:
            self.stop()


async def collect_cloud_flows(provider: str = "aws", duration: int = 60) -> List[Dict[str, Any]]:
    """
    Collect cloud flows for a specified duration.
    
    Args:
        provider: Cloud provider ('aws', 'azure', 'gcp')
        duration: Collection duration in seconds
    
    Returns:
        List of flow dictionaries
    """
    config = CloudFlowLogConfig(
        provider=CloudProvider(provider),
        poll_interval_seconds=1,
        batch_size=100,
    )

    agent = CloudFlowLogAgent(config)
    flows: List[Dict[str, Any]] = []

    await agent.start()

    deadline = asyncio.get_event_loop().time() + duration
    while asyncio.get_event_loop().time() < deadline:
        remaining = deadline - asyncio.get_event_loop().time()
        flow = await agent.get_flow(timeout=min(1.0, remaining))
        if flow:
            flows.append(flow)

    agent.stop()
    return flows