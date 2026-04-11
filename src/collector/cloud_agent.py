"""
Cloud Flow Log Agent

Collects flow logs from cloud providers (AWS VPC Flow Logs, GCP Flow Logs,
Azure NSG Flow Logs).  Provides a unified interface for cloud-native traffic
collection.
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class FlowParseException(ValueError):
    """Custom exception for flow parsing errors."""
    pass



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
    max_queue_size: int = 10_000
    include_metadata: bool = True


def _safe_int(value: Any, default: int = 0) -> int:
    """
    Convert *value* to int, returning *default* for non-numeric strings
    such as the "-" placeholder used in AWS VPC Flow Logs when a field
    is not applicable (e.g. port numbers for ICMP flows).
    """
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


class CloudFlowLogAgent:
    """
    Unified agent for collecting flow logs from cloud providers.
    Supports AWS VPC Flow Logs, Azure NSG Flow Logs, and GCP Flow Logs.
    """

    def __init__(
        self,
        config: CloudFlowLogConfig,
        flow_handler: Optional[Callable] = None,
    ) -> None:
        self.config = config
        self.flow_handler = flow_handler
        self.is_running = False

        self.flow_queue: Optional[asyncio.Queue] = None
        self._poll_task: Optional[asyncio.Task] = None

        self._aws_client: Any = None
        self._azure_client: Any = None
        self._gcp_client: Any = None

        self._aws_stream_tokens: Dict[str, str] = {}

        self.stats: Dict[str, Any] = {
            'flows_processed': 0,
            'flows_dropped': 0,
            'api_errors': 0,
            'last_successful_poll': None,
        }

        logger.info(f"CloudFlowLogAgent initialised for provider: {config.provider.value}")

    # ------------------------------------------------------------------
    # Lazy client initialisation
    # ------------------------------------------------------------------

    def _get_aws_client(self) -> Any:
        """Lazy-load synchronous AWS CloudWatch Logs client (boto3)."""
        if self._aws_client is None:
            try:
                import boto3  # type: ignore
                self._aws_client = boto3.client('logs', region_name=self.config.region)
                logger.info("AWS CloudWatch Logs client initialised")
            except ImportError:
                logger.error("boto3 not installed.  Install with: pip install boto3")
                raise
            except Exception as exc:
                logger.error(f"Failed to initialise AWS client: {exc}")
                raise
        return self._aws_client

    def _get_azure_client(self) -> Any:
        """Lazy-load Azure NetworkManagementClient."""
        if self._azure_client is None:
            try:
                from azure.mgmt.network import NetworkManagementClient  # type: ignore
                from azure.identity import DefaultAzureCredential  # type: ignore

                credential = DefaultAzureCredential()
                self._azure_client = NetworkManagementClient(
                    credential=credential,
                    subscription_id=self.config.azure_subscription_id,
                )
                logger.info("Azure Network client initialised")
            except ImportError:
                logger.error(
                    "Azure SDK not installed.  "
                    "Install with: pip install azure-mgmt-network azure-identity"
                )
                raise
            except Exception as exc:
                logger.error(f"Failed to initialise Azure client: {exc}")
                raise
        return self._azure_client

    def _get_gcp_client(self) -> Any:
        """Lazy-load GCP Logging client."""
        if self._gcp_client is None:
            try:
                from google.cloud import logging as gcp_logging  # type: ignore

                self._gcp_client = gcp_logging.Client(project=self.config.gcp_project_id)
                logger.info("GCP Logging client initialised")
            except ImportError:
                logger.error(
                    "Google Cloud SDK not installed.  "
                    "Install with: pip install google-cloud-logging"
                )
                raise
            except Exception as exc:
                logger.error(f"Failed to initialise GCP client: {exc}")
                raise
        return self._gcp_client

    # ------------------------------------------------------------------
    # AWS polling
    # ------------------------------------------------------------------

    async def _poll_aws_flow_logs(self) -> None:
        """
        Poll AWS VPC Flow Logs from CloudWatch Logs.

        FIX BUG-15: boto3 is synchronous and must not be called directly from
        an async coroutine — it blocks the entire event loop.  All blocking
        boto3 calls are now offloaded to a thread-pool executor.
        """
        loop = asyncio.get_running_loop()
        client = self._get_aws_client()

        for log_group in self.config.aws_log_group_names:
            try:
                # Blocking boto3 call → run in executor
                streams_response = await loop.run_in_executor(
                    None,
                    lambda lg=log_group: client.describe_log_streams(
                        logGroupName=lg,
                        orderBy='LastEventTime',
                        descending=True,
                        limit=10,
                    ),
                )

                for stream in streams_response.get('logStreams', []):
                    stream_name = stream['logStreamName']
                    stream_key = f"{log_group}/{stream_name}"

                    kwargs: Dict[str, Any] = {
                        'logGroupName': log_group,
                        'logStreamName': stream_name,
                        'startFromHead': False,
                        'limit': self.config.batch_size,
                    }
                    if stream_key in self._aws_stream_tokens:
                        kwargs['nextToken'] = self._aws_stream_tokens[stream_key]

                    # Blocking boto3 call → run in executor
                    events_response = await loop.run_in_executor(
                        None,
                        lambda kw=kwargs: client.get_log_events(**kw),
                    )

                    next_token = events_response.get('nextForwardToken')
                    if next_token:
                        self._aws_stream_tokens[stream_key] = next_token

                    for event in events_response.get('events', []):
                        flow = self._parse_aws_flow_log(
                            event['message'], event['timestamp']
                        )
                        if flow and self.flow_queue:
                            await self.flow_queue.put(flow)
                            self.stats['flows_processed'] += 1

            except Exception as exc:
                logger.error(f"Error polling AWS flow logs from {log_group}: {exc}")
                self.stats['api_errors'] += 1

    def _parse_aws_flow_log(
        self, log_message: str, timestamp: int
    ) -> Optional[Dict[str, Any]]:
        """
        Parse an AWS VPC Flow Log entry.

        Standard format (14+ space-separated fields):
          version account-id interface-id srcaddr dstaddr srcport dstport
          protocol packets bytes start end action log-status

        FIX BUG-13: Port fields contain "-" for ICMP (which has no ports).
          int() on "-" raises ValueError.  Use _safe_int() with default 0.

        FIX BUG-14: packets and bytes fields are also "-" for REJECT-logged
          flows where the log-status is NODATA or SKIPDATA.  Same fix applies.
        """
        fields = log_message.strip().split()
        if len(fields) < 14:
            raise FlowParseException(f"Invalid AWS flow log format: {len(fields)} fields")

        return {
            'timestamp': timestamp / 1000.0,        # Convert ms → seconds
            'source': 'aws_vpc_flow_logs',
            'ip_src': fields[3],
            'ip_dst': fields[4],
            'sport': _safe_int(fields[5], 0),       # FIX BUG-13
            'dport': _safe_int(fields[6], 0),       # FIX BUG-13
            'protocol': _safe_int(fields[7], 0),
            'packets': _safe_int(fields[8], 0),     # FIX BUG-14
            'bytes': _safe_int(fields[9], 0),       # FIX BUG-14
            'action': fields[12],
            'log_status': fields[13],
            'interface_id': fields[2],
            'account_id': fields[1],
            'flow_direction': 'forward',
        }


    # ------------------------------------------------------------------
    # Azure polling
    # ------------------------------------------------------------------

    async def _poll_azure_flow_logs(self) -> None:
        """
        Poll Azure NSG Flow Logs.

        FIX BUG-16: The Azure SDK is synchronous; the client initialisation
        and any network calls must be offloaded to an executor.
        """
        loop = asyncio.get_running_loop()

        try:
            # Initialise the client in the executor to avoid blocking the loop
            # during the credential discovery (which may hit the network).
            await loop.run_in_executor(None, self._get_azure_client)
            logger.info(
                "Polling Azure NSG flow logs "
                "(production implementation reads from Azure Storage / Event Hubs)"
            )
            # Production: read blobs or Event Hub events here, offloading any
            # blocking I/O with run_in_executor().
            await asyncio.sleep(self.config.poll_interval_seconds)

        except Exception as exc:
            logger.error(f"Error polling Azure flow logs: {exc}")
            self.stats['api_errors'] += 1

    def _parse_azure_flow_log(
        self, log_entry: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Parse an Azure NSG Flow Log entry."""
        raw_ts = log_entry.get('time') or log_entry.get('timestamp')
        if isinstance(raw_ts, str):
            ts = datetime.fromisoformat(raw_ts.rstrip('Z')).timestamp()
        elif isinstance(raw_ts, (int, float)):
            ts = float(raw_ts)
        else:
            ts = datetime.utcnow().timestamp()

        protocol_str = log_entry.get('protocol', 'TCP').upper()
        protocol_num = 6 if protocol_str == 'TCP' else (17 if protocol_str == 'UDP' else 1)

        flow: Dict[str, Any] = {
            'timestamp': ts,
            'source': 'azure_nsg_flow_logs',
            'ip_src': log_entry.get('srcIP'),
            'ip_dst': log_entry.get('dstIP'),
            'sport': _safe_int(log_entry.get('srcPort', 0)),
            'dport': _safe_int(log_entry.get('dstPort', 0)),
            'protocol': protocol_num,
            'packets': _safe_int(log_entry.get('packetsSent', 0)),
            'bytes': _safe_int(log_entry.get('bytesSent', 0)),
            'action': log_entry.get('flowStatus', 'ALLOWED'),
        }
        if not all([flow['ip_src'], flow['ip_dst']]):
            raise FlowParseException("Missing srcIP or dstIP in Azure flow log")
        return flow


    # ------------------------------------------------------------------
    # GCP polling
    # ------------------------------------------------------------------

    async def _poll_gcp_flow_logs(self) -> None:
        """
        Poll GCP VPC Flow Logs.

        FIX BUG-17: client.list_entries() is a synchronous, blocking iterator
        that can stall the event loop for hundreds of milliseconds on large
        result sets.  Offload to run_in_executor().
        """
        loop = asyncio.get_running_loop()
        client = self._get_gcp_client()
        filter_str = 'logName:"flows" AND severity>=INFO'

        try:
            # Fetch log entries without blocking the event loop
            entries = await loop.run_in_executor(
                None,
                lambda: list(
                    client.list_entries(
                        filter_=filter_str,
                        max_results=self.config.batch_size,
                    )
                ),
            )
            for entry in entries:
                flow = self._parse_gcp_flow_log(entry)
                if flow and self.flow_queue:
                    await self.flow_queue.put(flow)
                    self.stats['flows_processed'] += 1

        except Exception as exc:
            logger.error(f"Error polling GCP flow logs: {exc}")
            self.stats['api_errors'] += 1

    def _parse_gcp_flow_log(self, log_entry: Any) -> Optional[Dict[str, Any]]:
        """Parse a GCP VPC Flow Log entry."""
        payload = log_entry.payload
        if 'connection' not in payload:
            raise FlowParseException("Missing 'connection' in GCP flow log payload")

        conn = payload['connection']
        protocol = _safe_int(conn.get('protocol', 17), 17)

        disposition = payload.get('disposition', 'ALLOWED').upper()
        action = 'DENIED' if disposition == 'DENIED' else 'ALLOWED'

        return {
            'timestamp': log_entry.timestamp.timestamp(),
            'source': 'gcp_vpc_flow_logs',
            'ip_src': conn.get('src_ip'),
            'ip_dst': conn.get('dest_ip'),
            'sport': _safe_int(conn.get('src_port', 0)),
            'dport': _safe_int(conn.get('dest_port', 0)),
            'protocol': protocol,
            'packets': _safe_int(payload.get('packets_sent', 0)),
            'bytes': _safe_int(payload.get('bytes_sent', 0)),
            'action': action,
        }


    # ------------------------------------------------------------------
    # Main polling loop
    # ------------------------------------------------------------------

    async def _poll_loop(self) -> None:
        """Main polling loop for all cloud providers."""
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

            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error(f"Error in cloud flow log polling loop: {exc}")
                await asyncio.sleep(5)   # Back off on error

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start flow log collection."""
        self.flow_queue = asyncio.Queue(maxsize=self.config.max_queue_size)
        self.is_running = True
        self._poll_task = asyncio.create_task(self._poll_loop())

    def stop(self) -> None:
        """Stop flow log collection."""
        logger.info("Stopping cloud flow log collection")
        self.is_running = False
        if self._poll_task:
            self._poll_task.cancel()

    async def get_flow(self, timeout: Optional[float] = None) -> Optional[Dict[str, Any]]:
        """Get the next flow from the internal queue."""
        if self.flow_queue is None:
            return None
        try:
            return await asyncio.wait_for(self.flow_queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None

    def get_stats(self) -> Dict[str, Any]:
        """Return collection statistics."""
        return {
            **self.stats,
            'queue_size': self.flow_queue.qsize() if self.flow_queue else 0,
            'is_running': self.is_running,
            'provider': self.config.provider.value,
        }

    async def run_pipeline(self, flow_builder: Any) -> None:
        """Run the complete agent-to-flow-builder pipeline."""
        await self.start()

        try:
            while self.is_running:
                flow_dict = await self.get_flow(timeout=1.0)
                if flow_dict and flow_builder:
                    packet_format: Dict[str, Any] = {
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


# ---------------------------------------------------------------------------
# Convenience helper
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Example usage for testing the CloudFlowLogAgent
    async def main():
        logging.basicConfig(level=logging.INFO)
        
        # --- Configuration ---
        # Set the provider to 'aws', 'azure', or 'gcp'
        # Note: This example uses mock data and does not connect to a real cloud provider.
        PROVIDER = "aws"
        DURATION = 10 # seconds
        
        config = CloudFlowLogConfig(
            provider=CloudProvider(PROVIDER),
            poll_interval_seconds=1,
            batch_size=10,
            # Add mock-specific config if needed, e.g., mock log groups
            aws_log_group_names=["/aws/vpcflow/mock-log-group"]
        )

        agent = CloudFlowLogAgent(config)

        # --- Mocking the cloud provider client ---
        # This is a simplified mock. A more robust test would use a library like `moto` for AWS.
        if PROVIDER == "aws":
            from unittest.mock import MagicMock
            
            mock_boto_client = MagicMock()
            
            # Mock `describe_log_streams`
            mock_boto_client.describe_log_streams.return_value = {
                'logStreams': [{'logStreamName': 'mock-stream-1'}]
            }
            
            # Mock `get_log_events` to return some sample flow logs
            mock_boto_client.get_log_events.return_value = {
                'events': [
                    {
                        'timestamp': int(time.time() * 1000),
                        'message': "2 123456789012 eni-12345678 192.168.1.1 10.0.0.1 12345 80 6 10 1234 1622547800 1622547860 ACCEPT OK"
                    },
                    {
                        'timestamp': int(time.time() * 1000),
                        'message': "2 123456789012 eni-12345678 10.0.0.2 8.8.8.8 54321 53 17 1 60 1622547801 1622547861 ACCEPT OK"
                    }
                ],
                'nextForwardToken': 'mock-token'
            }
            agent._get_aws_client = MagicMock(return_value=mock_boto_client)

        # --- Run the agent and collect flows ---
        print(f"Starting agent to collect '{PROVIDER}' flows for {DURATION} seconds...")
        collected_flows = await collect_cloud_flows(provider=PROVIDER, duration=DURATION)
        
        print(f"\nCollected {len(collected_flows)} flows:")
        for i, flow in enumerate(collected_flows):
            print(f"  {i+1}: {flow}")
            
        # You can also run the pipeline with a mock flow builder
        # from flow_builder import FlowBuilder
        # flow_builder = FlowBuilder()
        # await agent.run_pipeline(flow_builder)

    asyncio.run(main())