#!/usr/bin/env python3
"""
Generate secure secrets for the DDoS detection system.
"""

import secrets
import string
import argparse
import os
from pathlib import Path

def generate_jwt_secret(length=64):
    """Generate cryptographically secure JWT secret"""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def generate_api_key():
    """Generate secure API key with prefix"""
    random_part = secrets.token_urlsafe(32)
    return f"cks_{random_part}"

def update_env_file(env_path: Path, updates: dict):
    """Safely update .env file"""
    if not env_path.exists():
        print(f"Error: {env_path} not found")
        return False
    
    # Read existing lines
    with open(env_path, 'r') as f:
        lines = f.readlines()
    
    updated = set()
    new_lines = []
    
    for line in lines:
        # Check if line is a key we want to update
        updated_this_line = False
        for key, value in updates.items():
            if line.startswith(f"{key}="):
                new_lines.append(f"{key}={value}\n")
                updated.add(key)
                updated_this_line = True
                break
        if not updated_this_line:
            new_lines.append(line)
    
    # Add missing keys
    for key, value in updates.items():
        if key not in updated:
            new_lines.append(f"{key}={value}\n")
    
    # Write back
    with open(env_path, 'w') as f:
        f.writelines(new_lines)
    
    print(f"Updated {len(updates)} secrets in {env_path}")
    return True

def main():
    parser = argparse.ArgumentParser(description="Generate secure secrets")
    parser.add_argument("--env-file", default=".env", help="Path to .env file")
    parser.add_argument("--force", action="store_true", help="Overwrite existing secrets")
    args = parser.parse_args()
    
    # Check if .env exists
    env_path = Path(args.env_file)
    if not env_path.exists():
        print(f"Error: {args.env_file} not found. Create it from .env.example first.")
        return 1
    
    updates = {
        "API_JWT_SECRET_KEY": generate_jwt_secret(),
        "API_API_KEY": generate_api_key(),
        "REDIS_PASSWORD": secrets.token_urlsafe(32),
        "POSTGRES_PASSWORD": secrets.token_urlsafe(32),
    }
    
    if args.force:
        update_env_file(env_path, updates)
        print("\n✅ Secrets generated successfully!")
        print("⚠️  Store these securely - never commit to git!")
        return 0
    else:
        response = input("Generate new secrets? (y/N): ").strip().lower()
        if response == 'y':
            update_env_file(env_path, updates)
            print("\n✅ Secrets generated successfully!")
            print("⚠️  Store these securely - never commit to git!")
            return 0
        else:
            print("Skipped secret generation")
            return 0

if __name__ == "__main__":
    exit(main())