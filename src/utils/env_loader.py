#!/usr/bin/env python3
"""
Safe .env loader for DDoS system.
Loads .env.template → .env → os.environ fallback.
Validates required vars for environment.
"""
import os
from pathlib import Path
from typing import Dict, Any, Optional
from dotenv import load_dotenv

def load_env(env_file: Optional[str] = None, required_vars: Optional[list] = None) -> Dict[str, str]:
    """
    Load environment from .env file, validate required vars.
    
    Args:
        env_file: Path to .env file (default: project root .env)
        required_vars: List of required env var names
        
    Returns:
        Dict of loaded env vars
    """
    project_root = Path(__file__).parent.parent.parent
    env_path = project_root / (env_file or '.env')
    
    # Load .env if exists
    if env_path.exists():
        load_dotenv(env_path)
        print(f"[OK] Loaded {env_path}")
    else:
        print(f"[WARN] {env_path} not found, using system env")
    
    # Validate required vars
    missing = []
    env_dict = {}
    for key, value in os.environ.items():
        env_dict[key] = value
    
    if required_vars:
        for var in required_vars:
            if not os.environ.get(var):
                missing.append(var)
    
    if missing:
        raise ValueError(f"[ERROR] Missing required env vars: {', '.join(missing)}")
    
    print(f"[OK] Env loaded: {len(env_dict)} vars")
    return env_dict

def get_required_env(required: list) -> Dict[str, str]:
    """Get required env vars or raise error."""
    return load_env(required_vars=required)

# Common var sets
CORE_VARS = [
    'KAFKA_BOOTSTRAP_SERVERS', 'REDIS_HOST', 'API_KEY',
    'GRAFANA_ADMIN_USER', 'GRAFANA_ADMIN_PASS'
]

LOCAL_VARS = CORE_VARS + ['KAFKA_TOPIC_FLOWS']
CLOUD_VARS = LOCAL_VARS + ['AWS_REGION', 'AWS_ACCOUNT_ID']

if __name__ == '__main__':
    # Test loader
    try:
        env = load_env()
        print("Sample vars:", {k: v[:10]+'...' if len(v)>10 else v 
                             for k, v in list(env.items())[:5]})
    except Exception as e:
        print(f"❌ Env error: {e}")

