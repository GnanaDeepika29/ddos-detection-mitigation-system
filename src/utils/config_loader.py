"""
Configuration Loader Module

Loads configuration from multiple sources with priority:
1. Environment variables
2. YAML configuration files
3. Default values

Supports nested configuration, validation, and hot reloading.
"""

import os
import yaml
import json
from pathlib import Path
from typing import Dict, Any, Optional, Union, List
from dataclasses import dataclass, field, asdict

from src.utils.paths import resolve_project_path

# Try to load dotenv, but don't fail if not available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


@dataclass
class AppConfig:
    """Main application configuration"""

    # Application settings
    environment: str = "development"
    debug: bool = False
    log_level: str = "INFO"
    service_name: str = "ddos-protection"
    service_version: str = "1.0.0"
    host: str = "0.0.0.0"
    port: int = 8000

    # Detection settings
    detection_window_seconds: int = 5
    detection_pps_threshold: int = 10000
    detection_bps_threshold: int = 100000000
    detection_entropy_threshold: float = 0.7

    # Kafka settings
    kafka_bootstrap_servers: str = "localhost:9092"
    kafka_topic_flows: str = "network_flows"
    kafka_topic_alerts: str = "ddos_alerts"
    kafka_consumer_group: str = "ddos-detection-group"

    # Redis settings
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_password: str = ""
    redis_db: int = 0

    # Cloud settings
    cloud_provider: str = "none"
    cloud_region: str = "us-east-1"

    # Mitigation settings
    auto_mitigate: bool = False
    mitigation_dry_run: bool = True

    # Metrics settings
    metrics_enabled: bool = True
    metrics_port: int = 9091

    # Alert settings
    alert_min_severity: str = "medium"
    alert_cooldown_seconds: int = 30

    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary"""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AppConfig':
        """Create config from dictionary"""
        return cls(**{k: v for k, v in data.items() if hasattr(cls, k)})


class ConfigLoader:
    """
    Configuration loader with support for multiple sources.
    Priority: Environment > YAML file > Defaults
    """

    def __init__(self, config_path: Optional[Union[str, Path]] = None):
        self.config_path = resolve_project_path(config_path) if config_path else None
        self._config: Optional[AppConfig] = None
        self._env_prefix = "DDOS_"
        self.load()

    def _load_from_file(self) -> Dict[str, Any]:
        """Load configuration from YAML file."""
        if not self.config_path or not self.config_path.exists():
            return {}

        try:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
                return config or {}
        except yaml.YAMLError as e:
            print(f"Error parsing YAML config: {e}")
            return {}
        except Exception as e:
            print(f"Error loading config file: {e}")
            return {}

    def _load_from_env(self) -> Dict[str, Any]:
        """Load configuration from environment variables."""
        config = {}

        for env_key, env_value in os.environ.items():
            if not env_key.startswith(self._env_prefix):
                continue

            # DDOS_KAFKA_BOOTSTRAP_SERVERS → kafka_bootstrap_servers
            config_key = env_key[len(self._env_prefix):].lower()
            
            # Handle nested keys with double underscore
            config_key = config_key.replace('__', '.')

            # Parse value (try JSON first for booleans/integers, then string)
            try:
                parsed_value = json.loads(env_value)
            except json.JSONDecodeError:
                parsed_value = env_value

            # Handle nested configuration
            keys = config_key.split('.')
            current = config
            for key in keys[:-1]:
                if key not in current:
                    current[key] = {}
                current = current[key]
            current[keys[-1]] = parsed_value

        return config

    def _merge_configs(self, default: Dict[str, Any],
                       file_config: Dict[str, Any],
                       env_config: Dict[str, Any]) -> Dict[str, Any]:
        """Merge configurations with priority: env > file > default."""
        result = default.copy()
        self._deep_merge(result, file_config)
        self._deep_merge(result, env_config)
        return result

    def _deep_merge(self, base: Dict[str, Any], override: Dict[str, Any]):
        """Deep merge two dictionaries in-place."""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value

    def _apply_type_conversions(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Apply type conversions for known configuration keys."""
        
        bool_keys = ['debug', 'auto_mitigate', 'mitigation_dry_run', 'metrics_enabled']
        for key in bool_keys:
            if key in config and isinstance(config[key], str):
                config[key] = config[key].lower() in ['true', 'yes', '1', 'on']

        int_keys = [
            'port', 'detection_window_seconds', 'detection_pps_threshold',
            'detection_bps_threshold', 'redis_port', 'redis_db',
            'metrics_port', 'alert_cooldown_seconds',
        ]
        for key in int_keys:
            if key in config:
                v = config[key]
                if isinstance(v, str) and not isinstance(v, bool):
                    try:
                        config[key] = int(v)
                    except ValueError:
                        pass

        float_keys = ['detection_entropy_threshold']
        for key in float_keys:
            if key in config:
                v = config[key]
                if isinstance(v, str) and not isinstance(v, bool):
                    try:
                        config[key] = float(v)
                    except ValueError:
                        pass

        return config

    def _flatten_config(self, config: Dict[str, Any], parent_key: str = '') -> Dict[str, Any]:
        """Flatten nested configuration dictionary"""
        items = []
        for k, v in config.items():
            new_key = f"{parent_key}.{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_config(v, new_key).items())
            else:
                items.append((new_key, v))
        return dict(items)

    def load(self) -> 'AppConfig':
        """Load configuration from all sources."""
        default_config = asdict(AppConfig())
        file_config = self._load_from_file()
        env_config = self._load_from_env()

        merged_config = self._merge_configs(default_config, file_config, env_config)
        merged_config = self._apply_type_conversions(merged_config)

        self._config = AppConfig.from_dict(merged_config)
        return self._config

    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value by dot-notation key."""
        if not self._config:
            self.load()

        keys = key.split('.')
        value = self._config.to_dict()

        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
                if value is None:
                    return default
            else:
                return default

        return value

    def reload(self):
        """Reload configuration from sources."""
        self.load()

    def get_all(self) -> Dict[str, Any]:
        """Get all configuration as dictionary"""
        if not self._config:
            self.load()
        return self._config.to_dict()

    def get_config(self) -> 'AppConfig':
        """Get the AppConfig object"""
        if not self._config:
            self.load()
        return self._config


_global_config: Optional[ConfigLoader] = None


def load_config(config_path: Optional[Union[str, Path]] = None) -> AppConfig:
    """Load configuration globally"""
    global _global_config
    _global_config = ConfigLoader(config_path)
    return _global_config.get_config()


def get_config_value(key: str, default: Any = None) -> Any:
    """Get a configuration value from the global config"""
    if _global_config:
        return _global_config.get(key, default)
    
    # Fallback to environment variable
    env_key = f"DDOS_{key.upper().replace('.', '_')}"
    return os.environ.get(env_key, default)


def reload_config():
    """Reload the global configuration"""
    if _global_config:
        _global_config.reload()


# Configuration validation schema
CONFIG_SCHEMA = {
    'environment': {'type': str, 'allowed': ['development', 'staging', 'production']},
    'debug': {'type': bool},
    'log_level': {'type': str, 'allowed': ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']},
    'detection_window_seconds': {'type': int, 'min': 1, 'max': 60},
    'detection_pps_threshold': {'type': int, 'min': 0},
    'auto_mitigate': {'type': bool},
    'cloud_provider': {'type': str, 'allowed': ['aws', 'azure', 'gcp', 'none']},
}


def validate_config(config: AppConfig) -> List[str]:
    """Validate configuration against schema"""
    errors = []
    config_dict = config.to_dict()

    for key, rules in CONFIG_SCHEMA.items():
        value = config_dict.get(key)
        expected_type = rules['type']

        # Type checking
        if expected_type == bool:
            if not isinstance(value, bool):
                errors.append(f"{key} must be boolean, got {type(value).__name__}")
        elif expected_type == int:
            # Reject booleans masquerading as ints (isinstance(True, int) is True)
            if isinstance(value, bool) or not isinstance(value, int):
                errors.append(f"{key} must be integer, got {type(value).__name__}")
        elif expected_type == str:
            if not isinstance(value, str):
                errors.append(f"{key} must be string, got {type(value).__name__}")

        # Allowed values
        if 'allowed' in rules and value not in rules['allowed']:
            errors.append(f"{key} must be one of {rules['allowed']}, got {value!r}")

        # Min/max bounds
        if 'min' in rules and isinstance(value, (int, float)) and not isinstance(value, bool):
            if value < rules['min']:
                errors.append(f"{key} must be >= {rules['min']}, got {value}")

        if 'max' in rules and isinstance(value, (int, float)) and not isinstance(value, bool):
            if value > rules['max']:
                errors.append(f"{key} must be <= {rules['max']}, got {value}")

    return errors
