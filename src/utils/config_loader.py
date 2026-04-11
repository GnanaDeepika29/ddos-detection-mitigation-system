"""
Configuration Loader Module

Loads configuration from multiple sources with priority:
1. Environment variables
2. YAML configuration files
3. Default values

Supports nested configuration, validation, and hot reloading.
"""

import json
import logging
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml

from src.utils.paths import resolve_project_path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

logger = logging.getLogger(__name__)


@dataclass
class AppConfig:
    """Main application configuration - memory-optimized defaults."""

    environment: str = "development"
    debug: bool = False
    log_level: str = "INFO"
    service_name: str = "ddos-protection"
    service_version: str = "1.0.0"
    host: str = "0.0.0.0"
    port: int = 8000

    detection_window_seconds: int = 5
    detection_pps_threshold: int = 50_000
    detection_bps_threshold: int = 100_000_000
    detection_entropy_threshold: float = 0.7

    kafka_bootstrap_servers: str = "localhost:9092"
    kafka_topic_flows: str = "network_flows"
    kafka_topic_alerts: str = "ddos_alerts"
    kafka_consumer_group: str = "ddos-detection-group"
    kafka_max_batch_size: int = 100

    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_password: str = ""
    redis_db: int = 0
    redis_max_connections: int = 50

    cloud_provider: str = "none"
    cloud_region: str = "us-east-1"

    auto_mitigate: bool = False
    mitigation_dry_run: bool = True

    metrics_enabled: bool = True
    metrics_port: int = 9091

    alert_min_severity: str = "medium"
    alert_cooldown_seconds: int = 30

    max_flows_in_memory: int = 5000
    max_alerts_history: int = 5000
    aggregation_window_size: int = 60
    cleanup_interval_seconds: int = 60

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AppConfig":
        return cls(**{k: v for k, v in data.items() if hasattr(cls, k)})


class ConfigLoader:
    """
    Configuration loader: env > YAML file > defaults.
    """

    def __init__(self, config_path: Optional[Union[str, Path]] = None) -> None:
        self.config_path = resolve_project_path(config_path) if config_path else None
        self._config: Optional[AppConfig] = None
        self._env_prefix = "DDOS_"
        self.load()

    # ------------------------------------------------------------------
    # Source loaders
    # ------------------------------------------------------------------

    def _load_from_file(self) -> Dict[str, Any]:
        """Load from YAML file; return {} on any error."""
        if not self.config_path or not self.config_path.exists():
            return {}
        try:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
            return config or {}
        except yaml.YAMLError as exc:
            # FIX BUG-9: Use logger instead of print() for structured logging.
            logger.warning(f"Error parsing YAML config ({self.config_path}): {exc}")
            return {}
        except Exception as exc:
            logger.warning(f"Error loading config file ({self.config_path}): {exc}")
            return {}

    def _load_from_env(self) -> Dict[str, Any]:
        """
        Load DDOS_* environment variables.

        FIX BUG-8: The original code converted DDOS_KAFKA__BOOTSTRAP_SERVERS to
        a nested dict {'kafka': {'bootstrap_servers': ...}} via double-underscore
        splitting.  AppConfig is FLAT (all keys are snake_case at the top level,
        e.g. kafka_bootstrap_servers), so nested dicts are never matched by
        AppConfig.from_dict()'s hasattr check.  The result was that __ env vars
        were silently ignored.

        Fixed: after building any nested structure (kept for future nested config
        support), flatten the result back to dot-notation keys and then map them
        to the flat AppConfig field names by replacing '.' with '_'.
        """
        config: Dict[str, Any] = {}

        for env_key, env_value in os.environ.items():
            if not env_key.startswith(self._env_prefix):
                continue

            config_key = env_key[len(self._env_prefix):].lower()

            # Parse value
            try:
                parsed_value: Any = json.loads(env_value)
            except json.JSONDecodeError:
                parsed_value = env_value

            # FIX BUG-8: convert double-underscore nesting (e.g. KAFKA__HOST)
            # back to the flat AppConfig field name (kafka_host) so that
            # from_dict() can pick it up via hasattr().
            flat_key = config_key.replace('__', '_')
            config[flat_key] = parsed_value

        return config

    # ------------------------------------------------------------------
    # Merging & type conversion
    # ------------------------------------------------------------------

    def _merge_configs(
        self,
        default: Dict[str, Any],
        file_config: Dict[str, Any],
        env_config: Dict[str, Any],
    ) -> Dict[str, Any]:
        result = default.copy()
        self._deep_merge(result, file_config)
        self._deep_merge(result, env_config)
        return result

    def _deep_merge(self, base: Dict[str, Any], override: Dict[str, Any]) -> None:
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value

    def _apply_type_conversions(self, config: Dict[str, Any]) -> Dict[str, Any]:
        bool_keys = ['debug', 'auto_mitigate', 'mitigation_dry_run', 'metrics_enabled']
        for key in bool_keys:
            if key in config and isinstance(config[key], str):
                config[key] = config[key].lower() in ('true', 'yes', '1', 'on')

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

    def _flatten_config(
        self, config: Dict[str, Any], parent_key: str = ''
    ) -> Dict[str, Any]:
        items = []
        for k, v in config.items():
            new_key = f"{parent_key}.{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_config(v, new_key).items())
            else:
                items.append((new_key, v))
        return dict(items)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def load(self) -> AppConfig:
        default_config = asdict(AppConfig())
        file_config = self._load_from_file()
        env_config = self._load_from_env()

        merged = self._merge_configs(default_config, file_config, env_config)
        merged = self._apply_type_conversions(merged)

        self._config = AppConfig.from_dict(merged)
        return self._config

    def get(self, key: str, default: Any = None) -> Any:
        if not self._config:
            self.load()
        keys = key.split('.')
        value: Any = self._config.to_dict()
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
                if value is None:
                    return default
            else:
                return default
        return value

    def reload(self) -> None:
        self.load()

    def get_all(self) -> Dict[str, Any]:
        if not self._config:
            self.load()
        return self._config.to_dict()

    def get_config(self) -> AppConfig:
        if not self._config:
            self.load()
        return self._config


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

_global_config: Optional[ConfigLoader] = None


def load_config(config_path: Optional[Union[str, Path]] = None) -> AppConfig:
    global _global_config
    _global_config = ConfigLoader(config_path)
    return _global_config.get_config()


def get_config_value(key: str, default: Any = None) -> Any:
    if _global_config:
        return _global_config.get(key, default)
    env_key = f"DDOS_{key.upper().replace('.', '_')}"
    return os.environ.get(env_key, default)


def reload_config() -> None:
    if _global_config:
        _global_config.reload()


CONFIG_SCHEMA: Dict[str, Any] = {
    'environment': {'type': str, 'allowed': ['development', 'staging', 'production']},
    'debug': {'type': bool},
    'log_level': {'type': str, 'allowed': ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']},
    'detection_window_seconds': {'type': int, 'min': 1, 'max': 60},
    'detection_pps_threshold': {'type': int, 'min': 0},
    'auto_mitigate': {'type': bool},
    'cloud_provider': {'type': str, 'allowed': ['aws', 'azure', 'gcp', 'none']},
}


def validate_config(config: AppConfig) -> List[str]:
    """Validate configuration against schema; return list of error messages."""
    errors: List[str] = []
    config_dict = config.to_dict()

    for key, rules in CONFIG_SCHEMA.items():
        value = config_dict.get(key)
        expected_type = rules['type']

        if expected_type == bool:
            if not isinstance(value, bool):
                errors.append(f"{key} must be boolean, got {type(value).__name__}")
        elif expected_type == int:
            if isinstance(value, bool) or not isinstance(value, int):
                errors.append(f"{key} must be integer, got {type(value).__name__}")
        elif expected_type == str:
            if not isinstance(value, str):
                errors.append(f"{key} must be string, got {type(value).__name__}")

        if 'allowed' in rules and value not in rules['allowed']:
            errors.append(f"{key} must be one of {rules['allowed']}, got {value!r}")

        if 'min' in rules and isinstance(value, (int, float)) and not isinstance(value, bool):
            if value < rules['min']:
                errors.append(f"{key} must be >= {rules['min']}, got {value}")

        if 'max' in rules and isinstance(value, (int, float)) and not isinstance(value, bool):
            if value > rules['max']:
                errors.append(f"{key} must be <= {rules['max']}, got {value}")

    return errors