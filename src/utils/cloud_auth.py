"""
Cloud Authentication Module

Provides unified authentication for cloud providers (AWS, Azure, GCP).
Handles credential loading from multiple sources (env, files, instance metadata).
"""

import os
import json
import time
from pathlib import Path
from typing import Dict, Any, Optional, Union
from enum import Enum
from dataclasses import dataclass, field
import logging

logger = logging.getLogger(__name__)

_CLIENT_TTL_SECONDS = 3000  # ~50 minutes


class CloudProvider(Enum):
    """Supported cloud providers"""
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    NONE = "none"


@dataclass
class CloudCredentials:
    """Cloud provider credentials"""
    provider: CloudProvider
    access_key: Optional[str] = None
    secret_key: Optional[str] = None
    session_token: Optional[str] = None
    region: str = "us-east-1"

    # Azure specific
    tenant_id: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = field(default=None, repr=False)
    subscription_id: Optional[str] = None

    # GCP specific
    project_id: Optional[str] = None
    private_key_id: Optional[str] = None
    _private_key: Optional[str] = field(default=None, repr=False)
    client_email: Optional[str] = None

    @property
    def private_key(self) -> Optional[str]:
        """Get private key"""
        return self._private_key

    @private_key.setter
    def private_key(self, value: Optional[str]):
        """Set private key"""
        self._private_key = value

    def __repr__(self) -> str:
        # Safe repr - never includes private_key or client_secret
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
        """Check if credentials are valid"""
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
    Supports multiple credential sources with priority:
    1. Explicit credentials passed in
    2. Environment variables
    3. Credential files
    4. Instance metadata (IAM roles, managed identity, etc.)
    """

    def __init__(self, provider: CloudProvider = CloudProvider.NONE):
        self.provider = provider
        self._credentials: Optional[CloudCredentials] = None
        self._clients: Dict[str, tuple] = {}
        logger.info(f"CloudAuthenticator initialized for {provider.value}")

    def _load_from_env_aws(self) -> Optional[Dict[str, str]]:
        """Load AWS credentials from environment"""
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
        """Load Azure credentials from environment"""
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
        """Load GCP credentials from environment"""
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
            except Exception as e:
                logger.error(f"Failed to load GCP credentials file: {e}")

        if project_id:
            return {'project_id': project_id}
        return None

    def _load_from_file_aws(self) -> Optional[Dict[str, str]]:
        """Load AWS credentials from ~/.aws/credentials"""
        credentials_path = Path.home() / '.aws' / 'credentials'
        if not credentials_path.exists():
            return None

        try:
            import configparser
            config = configparser.ConfigParser()
            config.read(credentials_path)

            if 'default' in config:
                profile = config['default']
                creds = {
                    'access_key': profile.get('aws_access_key_id'),
                    'secret_key': profile.get('aws_secret_access_key'),
                    'session_token': profile.get('aws_session_token'),
                }

                # Load region from config if available
                config_path = Path.home() / '.aws' / 'config'
                if config_path.exists():
                    config.read(config_path)
                    if 'default' in config:
                        creds['region'] = config['default'].get('region', 'us-east-1')

                if creds['access_key'] and creds['secret_key']:
                    return creds
        except Exception as e:
            logger.error(f"Failed to load AWS credentials file: {e}")
        return None

    def _load_from_file_gcp(self) -> Optional[Dict[str, str]]:
        """Load GCP credentials from default locations"""
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
                except Exception as e:
                    logger.debug(f"Failed to load GCP credentials from {cred_path}: {e}")
        return None

    def _load_from_metadata_aws(self) -> Optional[Dict[str, str]]:
        """Load AWS credentials from instance metadata"""
        try:
            from botocore.utils import InstanceMetadataFetcher
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
        except Exception as e:
            logger.debug(f"Failed to load AWS metadata credentials: {e}")
        return None

    def _load_from_metadata_azure(self) -> Optional[Dict[str, str]]:
        """Load Azure credentials from managed identity"""
        try:
            import requests
            resp = requests.get(
                "http://169.254.169.254/metadata/identity/oauth2/token",
                headers={"Metadata": "true"},
                params={
                    "api-version": "2018-02-01",
                    "resource": "https://management.azure.com/"
                },
                timeout=2,
            )
            if resp.status_code == 200:
                # IMDS is reachable — signal managed identity mode
                return {'client_id': 'managed_identity'}
        except Exception as e:
            logger.debug(f"Azure IMDS not reachable: {e}")
        return None

    def load_credentials(self) -> Optional[CloudCredentials]:
        """Load credentials using the configured provider"""
        creds_dict = None

        if self.provider == CloudProvider.AWS:
            creds_dict = (self._load_from_env_aws()
                          or self._load_from_file_aws()
                          or self._load_from_metadata_aws())
            if creds_dict:
                self._credentials = CloudCredentials(
                    provider=self.provider,
                    access_key=creds_dict.get('access_key'),
                    secret_key=creds_dict.get('secret_key'),
                    session_token=creds_dict.get('session_token'),
                    region=creds_dict.get('region', 'us-east-1'),
                )

        elif self.provider == CloudProvider.AZURE:
            creds_dict = (self._load_from_env_azure()
                          or self._load_from_metadata_azure())
            if creds_dict:
                self._credentials = CloudCredentials(
                    provider=self.provider,
                    tenant_id=creds_dict.get('tenant_id'),
                    client_id=creds_dict.get('client_id'),
                    client_secret=creds_dict.get('client_secret'),
                    subscription_id=creds_dict.get('subscription_id'),
                )

        elif self.provider == CloudProvider.GCP:
            creds_dict = (self._load_from_env_gcp()
                          or self._load_from_file_gcp())
            if creds_dict:
                c = CloudCredentials(
                    provider=self.provider,
                    project_id=creds_dict.get('project_id'),
                    private_key_id=creds_dict.get('private_key_id'),
                    client_email=creds_dict.get('client_email'),
                )
                c.private_key = creds_dict.get('private_key')  # uses setter
                self._credentials = c

        if self._credentials and self._credentials.is_valid():
            logger.info(f"Loaded credentials for {self.provider.value}")
            return self._credentials

        logger.warning(f"No valid credentials found for {self.provider.value}")
        return None

    def get_credentials(self) -> Optional[CloudCredentials]:
        """Get credentials, loading if not already loaded"""
        if not self._credentials:
            self.load_credentials()
        return self._credentials

    def get_client(self, service: str) -> Any:
        """Get a cloud client for a specific service"""
        cache_key = f"{self.provider.value}:{service}"
        now = time.time()

        # Check cache
        if cache_key in self._clients:
            client, created_at = self._clients[cache_key]
            if now - created_at < _CLIENT_TTL_SECONDS:
                return client
            logger.debug(f"Client TTL expired for {cache_key}, recreating")

        # Create new client
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

    def _get_aws_client(self, service: str):
        """Get AWS service client"""
        try:
            import boto3
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
        except Exception as e:
            logger.error(f"Failed to create AWS client for {service}: {e}")
        return None

    def _get_azure_client(self, service: str):
        """Get Azure service client"""
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.network import NetworkManagementClient
            from azure.mgmt.monitor import MonitorManagementClient

            credentials = self.get_credentials()
            if not credentials:
                return None

            credential = DefaultAzureCredential()

            if service == 'network':
                return NetworkManagementClient(
                    credential=credential,
                    subscription_id=credentials.subscription_id,
                )
            elif service == 'monitor':
                return MonitorManagementClient(
                    credential=credential,
                    subscription_id=credentials.subscription_id,
                )
        except ImportError:
            logger.error("Azure SDK not installed")
        except Exception as e:
            logger.error(f"Failed to create Azure client for {service}: {e}")
        return None

    def _get_gcp_client(self, service: str):
        """Get GCP service client"""
        try:
            from google.cloud import compute_v1, logging_v2
            credentials = self.get_credentials()
            if not credentials:
                return None
                
            if service == 'compute':
                return compute_v1.InstancesClient()
            elif service == 'logging':
                return logging_v2.LoggingServiceV2Client()
        except ImportError:
            logger.error("Google Cloud SDK not installed")
        except Exception as e:
            logger.error(f"Failed to create GCP client for {service}: {e}")
        return None

    def set_credentials(self, credentials: CloudCredentials):
        """Manually set credentials"""
        self._credentials = credentials
        logger.info(f"Credentials manually set for {credentials.provider.value}")

    def clear_cache(self):
        """Clear client cache (forces recreation on next get_client call)"""
        self._clients.clear()
        logger.debug("Cloud client cache cleared")


_authenticators: Dict[str, CloudAuthenticator] = {}


def get_cloud_client(provider: Union[str, CloudProvider], service: str) -> Any:
    """Get a cloud client for the specified provider and service"""
    if isinstance(provider, str):
        provider = CloudProvider(provider.lower())
    
    key = provider.value
    if key not in _authenticators:
        _authenticators[key] = CloudAuthenticator(provider)
    
    return _authenticators[key].get_client(service)


def get_cloud_credentials(provider: Union[str, CloudProvider]) -> Optional[CloudCredentials]:
    """Get cloud credentials for the specified provider"""
    if isinstance(provider, str):
        provider = CloudProvider(provider.lower())
    
    key = provider.value
    if key not in _authenticators:
        _authenticators[key] = CloudAuthenticator(provider)
    
    return _authenticators[key].get_credentials()