#!/usr/bin/env python3
"""
Security audit for DDoS detection system.
"""

import os
import re
import secrets
import argparse
from pathlib import Path
from typing import Dict, List, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CERTS_DIR = PROJECT_ROOT / "certs"

class SecurityAuditor:
    def __init__(self, env_path: str = ".env"):
        env_candidate = Path(env_path)
        self.env_path = env_candidate if env_candidate.is_absolute() else PROJECT_ROOT / env_candidate
        self.violations = []
        
    def check_default_credentials(self) -> List[str]:
        """Check for default credentials"""
        if not self.env_path.exists():
            return ["No .env file found"]
        
        defaults = {
            'changeme': ['INFLUXDB_PASSWORD', 'ELASTICSEARCH_PASSWORD'],
            'admin': ['GRAFANA_PASSWORD', 'API_USER'],
            'password': ['POSTGRES_PASSWORD'],
            'root': ['MYSQL_ROOT_PASSWORD'],
        }
        
        violations = []
        try:
            with open(self.env_path, 'r') as f:
                content = f.read()
                
            for default, keys in defaults.items():
                for key in keys:
                    pattern = f"{key}=.*{default}.*"
                    if re.search(pattern, content, re.IGNORECASE):
                        violations.append(f"Default credential {key}={default}")
        except Exception as e:
            violations.append(f"Error reading .env: {e}")
        
        return violations
    
    def check_hardcoded_secrets(self) -> List[str]:
        """Check for hardcoded secrets"""
        if not self.env_path.exists():
            return ["No .env file found"]
        
        patterns: List[Tuple[str, str]] = [
            (r'API_JWT_SECRET_KEY=[a-f0-9]{32,}', 'Hardcoded JWT secret detected (hex pattern)'),
            (r'SECRET_KEY=[a-zA-Z0-9]{16,}', 'Generic hardcoded secret'),
        ]
        
        violations = []
        try:
            with open(self.env_path, 'r') as f:
                content = f.read()
                
            for pattern, message in patterns:
                if re.search(pattern, content):
                    violations.append(message)
        except Exception as e:
            violations.append(f"Error reading .env: {e}")
        
        return violations
    
    def check_tls_configuration(self) -> List[str]:
        """Check TLS configuration"""
        violations = []
        
        # Check if TLS certs exist
        if not (CERTS_DIR / "ca.crt").exists():
            violations.append("TLS certificates not found in ./certs/")
        
        # Check if .env has TLS enabled
        if self.env_path.exists():
            try:
                with open(self.env_path, 'r') as f:
                    content = f.read()
                if "INTERNAL_TLS_ENABLED=false" in content:
                    violations.append("TLS is disabled in configuration")
            except Exception:
                pass
        
        return violations
    
    def check_password_strength(self) -> List[str]:
        """Check password strength"""
        if not self.env_path.exists():
            return ["No .env file found"]
        
        violations = []
        try:
            with open(self.env_path, 'r') as f:
                content = f.read()
            
            # Check for weak passwords
            weak_patterns = [
                (r'PASSWORD=[a-zA-Z]+$', 'Password contains only letters'),
                (r'PASSWORD=[0-9]+$', 'Password contains only numbers'),
                (r'PASSWORD=.{1,7}$', 'Password is too short (< 8 chars)'),
            ]
            
            for pattern, message in weak_patterns:
                if re.search(pattern, content, re.MULTILINE):
                    violations.append(message)
                    
        except Exception as e:
            violations.append(f"Error reading .env: {e}")
        
        return violations
    
    def audit(self) -> Dict[str, List[str]]:
        """Run full security audit"""
        return {
            'default_credentials': self.check_default_credentials(),
            'hardcoded_secrets': self.check_hardcoded_secrets(),
            'missing_tls': self.check_tls_configuration(),
            'weak_passwords': self.check_password_strength(),
        }
    
import logging
logger = logging.getLogger(__name__)

def auto_fix(self):
        """Auto-fix common security issues"""
        if not self.env_path.exists():
            logger.error(f"Error: {self.env_path} not found")
            return False
        
        # Generate new secrets
        new_jwt = secrets.token_urlsafe(64)
        new_api_key = f"cks_{secrets.token_urlsafe(32)}"
        new_redis_pw = secrets.token_urlsafe(32)
        new_postgres_pw = secrets.token_urlsafe(32)
        
        # Update .env file
        with open(self.env_path, 'r') as f:
            lines = f.readlines()
        
        updated = False
        with open(self.env_path, 'w') as f:
            for line in lines:
                if line.startswith('API_JWT_SECRET_KEY='):
                    f.write(f'API_JWT_SECRET_KEY={new_jwt}\n')
                    updated = True
                elif line.startswith('API_API_KEY='):
                    f.write(f'API_API_KEY={new_api_key}\n')
                    updated = True
                elif line.startswith('REDIS_PASSWORD='):
                    f.write(f'REDIS_PASSWORD={new_redis_pw}\n')
                    updated = True
                elif line.startswith('POSTGRES_PASSWORD='):
                    f.write(f'POSTGRES_PASSWORD={new_postgres_pw}\n')
                    updated = True
                elif 'changeme' in line.lower():
                    # Skip lines with changeme (will be handled by specific matches)
                    if not any(line.startswith(k) for k in ['API_JWT_SECRET_KEY=', 'API_API_KEY=', 'REDIS_PASSWORD=', 'POSTGRES_PASSWORD=']):
                        f.write(line)
                else:
                    f.write(line)
        
        if updated:
            print("✅ Auto-fixed security issues")
            return True
        else:
            logger.info("No security issues auto-fixed")
            return False

def main():
    parser = argparse.ArgumentParser(description="Security audit for DDoS system")
    parser.add_argument("--fix", action="store_true", help="Auto-fix security issues")
    args = parser.parse_args()
    
    auditor = SecurityAuditor()
    
    if args.fix:
        auditor.auto_fix()
    else:
        results = auditor.audit()
        
        print("Security Audit Results:")
        print("=" * 40)
        
        has_issues = False
        for category, issues in results.items():
            print(f"\n{category.replace('_', ' ').title()}:")
            if issues:
                has_issues = True
                for issue in issues:
                    print(f"  ❌ {issue}")
            else:
                print("  ✅ No issues found")
        
        if has_issues:
            print("\n⚠️  Run with --fix to auto-fix some issues")
        else:
            print("\n✅ All security checks passed!")

if __name__ == "__main__":
    main()
