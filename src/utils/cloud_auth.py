"""
Cloud Authentication Module

Provides unified authentication for cloud providers (AWS, Azure, GCP).
Handles credential loading from multiple sources (env, files, instance metadata).
"""

import json
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional, Union
import logging

logger = logging.getLogger(__name__)

# FIX BUG-6: AWS IAM instance-role credentials expire every ~60 minutes.
# A 3000-second (50-minute) TTL means clients are reused for 50 minutes,
# but credentials could expire in the final 10 minutes of that window.
# Use 3300 seconds (55 minutes) to leave a 5-minute refresh buffer.
_CLIENT_TTL_SECONDS = 3300   # was 3000


class CloudProvider(Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    NONE = "none"


@dataclass
class CloudCredentials:
    """Cloud provider credentials."""
    provider: CloudProvider
    access_key: Optional[str] = None
    secret_key: Optional[str] = None
    session_token: Optional[str] = None
    region: str = "us-east-1"

    # Azure
    tenant_id: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = field(default=None, repr=False)
    subscription_id: Optional[str] = None

    # GCP
    project_id: Optional[str] = None
    private_key_id: Optional[str] = None
    _private_key: Optional[str] = field(default=None, repr=False)
    client_email: Optional[str] = None

    @property
    def private_key(self) -> Optional[str]:
        return self._private_key

    @private_key.setter
    def private_key(self, value: Optional[str]) -> None:
        self._private_key = value

    def __repr__(self) -> str:
        return (
            f"CloudCredentials(provider={self.provider.value!r}, "
            f"region={self.region!r}, "
            f"client_email={self.client_email!r}, "
            f"project_id={self.project_id!r}, "
            f"tenant_id={self.tenant_id!r}, "
            f"client_id={self.client_id!r}, "
            f"access_key={'***' if self.access_key else None}, "
            f"private_key=<redacted>, client_secret=<redacted>)"
        )

    def is_valid(self) -> bool:
        if self.provider == CloudProvider.AWS:
            return bool(self.access_key and self.secret_key)
        elif self.provider == CloudProvider.AZURE:
            if self.client_id == "managed_identity":
                return True
            return bool(self.tenant_id and self.client_id and self.client_secret)
        elif self.provider == CloudProvider.GCP:
            return bool(self.project_id and self._private_key)
        return True


class CloudAuthenticator:
    """
    Unified authenticator for cloud providers.
    Priority: explicit credentials → env vars → credential files → instance metadata.
    """

    def __init__(self, provider: CloudProvider = CloudProvider.NONE) -> None:
        self.provider = provider
        self._credentials: Optional[CloudCredentials] = None
        self._clients: Dict[str, tuple] = {}
        logger.info(f"CloudAuthenticator initialised for {provider.value}")

    # ------------------------------------------------------------------
    # Credential loaders
    # ------------------------------------------------------------------

    def _load_from_env_aws(self) -> Optional[Dict[str, str]]:
        access_key = os.environ.get('AWS_ACCESS_KEY_ID') or os.environ.get('AWS_ACCESS_KEY')
        secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY') or os.environ.get('AWS_SECRET_KEY')
        session_token = os.environ.get('AWS_SESSION_TOKEN')
        region = os.environ.get('AWS_REGION') or os.environ.get('AWS_DEFAULT_REGION', 'us-east-1')
        if access_key and secret_key:
            return {
                'access_key': access_key,
                'secret_key': secret_key,
                'session_token': session_token,
                'region': region,
            }
        return None

    def _load_from_env_azure(self) -> Optional[Dict[str, str]]:
        tenant_id = os.environ.get('AZURE_TENANT_ID')
        client_id = os.environ.get('AZURE_CLIENT_ID')
        client_secret = os.environ.get('AZURE_CLIENT_SECRET')
        subscription_id = os.environ.get('AZURE_SUBSCRIPTION_ID')
        if tenant_id and client_id and client_secret:
            return {
                'tenant_id': tenant_id,
                'client_id': client_id,
                'client_secret': client_secret,
                'subscription_id': subscription_id,
            }
        return None

    def _load_from_env_gcp(self) -> Optional[Dict[str, str]]:
        project_id = os.environ.get('GCP_PROJECT_ID') or os.environ.get('GOOGLE_CLOUD_PROJECT')
        credentials_path = os.environ.get('GOOGLE_APPLICATION_CREDENTIALS')
        if credentials_path and Path(credentials_path).exists():
            try:
                with open(credentials_path, 'r') as f:
                    sa = json.load(f)
                return {
                    'project_id': sa.get('project_id', project_id),
                    'private_key_id': sa.get('private_key_id'),
                    'private_key': sa.get('private_key'),
                    'client_email': sa.get('client_email'),
                }
            except Exception as exc:
                logger.error(f"Failed to load GCP credentials file: {exc}")
        if project_id:
            return {'project_id': project_id}
        return None

    def _load_from_file_aws(self) -> Optional[Dict[str, str]]:
        credentials_path = Path.home() / '.aws' / 'credentials'
        if not credentials_path.exists():
            return None
        try:
            import configparser
            config = configparser.ConfigParser()
            config.read(credentials_path)
            if 'default' in config:
                profile = config['default']
                creds: Dict[str, Any] = {
                    'access_key': profile.get('aws_access_key_id'),
                    'secret_key': profile.get('aws_secret_access_key'),
                    'session_token': profile.get('aws_session_token'),
                }
                config_path = Path.home() / '.aws' / 'config'
                if config_path.exists():
                    config.read(config_path)
                    if 'default' in config:
                        creds['region'] = config['default'].get('region', 'us-east-1')
                if creds['access_key'] and creds['secret_key']:
                    return creds
        except Exception as exc:
            logger.error(f"Failed to load AWS credentials file: {exc}")
        return None

    def _load_from_file_gcp(self) -> Optional[Dict[str, str]]:
        default_paths = [
            Path.home() / '.config' / 'gcloud' / 'application_default_credentials.json',
            Path('/etc/google/auth/application_default_credentials.json'),
        ]
        for cred_path in default_paths:
            if cred_path.exists():
                try:
                    with open(cred_path, 'r') as f:
                        creds = json.load(f)
                    return {
                        'project_id': creds.get('project_id'),
                        'private_key_id': creds.get('private_key_id'),
                        'private_key': creds.get('private_key'),
                        'client_email': creds.get('client_email'),
                    }
                except Exception as exc:
                    logger.debug(f"Failed to load GCP credentials from {cred_path}: {exc}")
        return None

    def _load_from_metadata_aws(self) -> Optional[Dict[str, str]]:
        """Load AWS credentials from EC2 instance metadata."""
        try:
            from botocore.utils import InstanceMetadataFetcher  # type: ignore
            fetcher = InstanceMetadataFetcher(timeout=1, num_attempts=2)
            creds = fetcher.retrieve_iam_role_credentials()
            if creds and creds.get('access_key'):
                return {
                    'access_key': creds.get('access_key'),
                    'secret_key': creds.get('secret_key'),
                    'session_token': creds.get('token'),
                }
        except ImportError:
            pass
        except Exception as exc:
            logger.debug(f"Failed to load AWS metadata credentials: {exc}")
        return None

    def _load_from_metadata_azure(self) -> Optional[Dict[str, str]]:
        """Detect Azure Managed Identity via IMDS."""
        try:
            import requests  # type: ignore
            resp = requests.get(
                "http://169.254.169.254/metadata/identity/oauth2/token",
                headers={"Metadata": "true"},
                params={"api-version": "2018-02-01", "resource": "https://management.azure.com/"},
                timeout=2,
            )
            if resp.status_code == 200:
                return {'client_id': 'managed_identity'}
        except Exception as exc:
            logger.debug(f"Azure IMDS not reachable: {exc}")
        return None

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def load_credentials(self) -> Optional[CloudCredentials]:
        """Load credentials using the configured provider."""
        creds_dict = None

        if self.provider == CloudProvider.AWS:
            creds_dict = (
                self._load_from_env_aws()
                or self._load_from_file_aws()
                or self._load_from_metadata_aws()
            )
            if creds_dict:
                self._credentials = CloudCredentials(
                    provider=self.provider,
                    access_key=creds_dict.get('access_key'),
                    secret_key=creds_dict.get('secret_key'),
                    session_token=creds_dict.get('session_token'),
                    region=creds_dict.get('region', 'us-east-1'),
                )

        elif self.provider == CloudProvider.AZURE:
            creds_dict = self._load_from_env_azure() or self._load_from_metadata_azure()
            if creds_dict:
                self._credentials = CloudCredentials(
                    provider=self.provider,
                    tenant_id=creds_dict.get('tenant_id'),
                    client_id=creds_dict.get('client_id'),
                    client_secret=creds_dict.get('client_secret'),
                    subscription_id=creds_dict.get('subscription_id'),
                )

        elif self.provider == CloudProvider.GCP:
            creds_dict = self._load_from_env_gcp() or self._load_from_file_gcp()
            if creds_dict:
                c = CloudCredentials(
                    provider=self.provider,
                    project_id=creds_dict.get('project_id'),
                    private_key_id=creds_dict.get('private_key_id'),
                    client_email=creds_dict.get('client_email'),
                )
                c.private_key = creds_dict.get('private_key')
                self._credentials = c

        if self._credentials and self._credentials.is_valid():
            logger.info(f"Loaded credentials for {self.provider.value}")
            return self._credentials

        logger.warning(f"No valid credentials found for {self.provider.value}")
        return None

    def get_credentials(self) -> Optional[CloudCredentials]:
        if not self._credentials:
            self.load_credentials()
        return self._credentials

    def get_client(self, service: str) -> Any:
        """Get a cached or newly-created cloud client for the given service."""
        cache_key = f"{self.provider.value}:{service}"
        now = time.time()

        if cache_key in self._clients:
            client, created_at = self._clients[cache_key]
            if now - created_at < _CLIENT_TTL_SECONDS:
                return client
            logger.debug(f"Client TTL expired for {cache_key}, recreating")

        client = None
        if self.provider == CloudProvider.AWS:
            client = self._get_aws_client(service)
        elif self.provider == CloudProvider.AZURE:
            client = self._get_azure_client(service)
        elif self.provider == CloudProvider.GCP:
            client = self._get_gcp_client(service)

        if client:
            self._clients[cache_key] = (client, now)

        return client

    def _get_aws_client(self, service: str) -> Any:
        try:
            import boto3  # type: ignore
            credentials = self.get_credentials()
            if not credentials:
                return None
            session = boto3.Session(
                aws_access_key_id=credentials.access_key,
                aws_secret_access_key=credentials.secret_key,
                aws_session_token=credentials.session_token,
                region_name=credentials.region,
            )
            return session.client(service)
        except ImportError:
            logger.error("boto3 not installed")
        except Exception as exc:
            logger.error(f"Failed to create AWS client for {service}: {exc}")
        return None

    def _get_azure_client(self, service: str) -> Any:
        try:
            from azure.identity import DefaultAzureCredential  # type: ignore
            from azure.mgmt.network import NetworkManagementClient  # type: ignore
            from azure.mgmt.monitor import MonitorManagementClient  # type: ignore

            credentials = self.get_credentials()
            if not credentials:
                return None
            credential = DefaultAzureCredential()
            if service == 'network':
                return NetworkManagementClient(
                    credential=credential, subscription_id=credentials.subscription_id
                )
            elif service == 'monitor':
                return MonitorManagementClient(
                    credential=credential, subscription_id=credentials.subscription_id
                )
        except ImportError:
            logger.error("Azure SDK not installed")
        except Exception as exc:
            logger.error(f"Failed to create Azure client for {service}: {exc}")
        return None

    def _get_gcp_client(self, service: str) -> Any:
        try:
            from google.cloud import compute_v1, logging_v2  # type: ignore
            credentials = self.get_credentials()
            if not credentials:
                return None
            if service == 'compute':
                return compute_v1.InstancesClient()
            elif service == 'logging':
                return logging_v2.LoggingServiceV2Client()
        except ImportError:
            logger.error("Google Cloud SDK not installed")
        except Exception as exc:
            logger.error(f"Failed to create GCP client for {service}: {exc}")
        return None

    def set_credentials(self, credentials: CloudCredentials) -> None:
        self._credentials = credentials
        logger.info(f"Credentials manually set for {credentials.provider.value}")

    def clear_cache(self) -> None:
        """Clear client cache (forces recreation on next get_client call)."""
        self._clients.clear()
        logger.debug("Cloud client cache cleared")


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

_authenticators: Dict[str, CloudAuthenticator] = {}


def get_cloud_client(provider: Union[str, CloudProvider], service: str) -> Any:
    if isinstance(provider, str):
        provider = CloudProvider(provider.lower())
    key = provider.value
    if key not in _authenticators:
        _authenticators[key] = CloudAuthenticator(provider)
    return _authenticators[key].get_client(service)


def get_cloud_credentials(
    provider: Union[str, CloudProvider],
) -> Optional[CloudCredentials]:
    if isinstance(provider, str):
        provider = CloudProvider(provider.lower())
    key = provider.value
    if key not in _authenticators:
        _authenticators[key] = CloudAuthenticator(provider)
    return _authenticators[key].get_credentials()