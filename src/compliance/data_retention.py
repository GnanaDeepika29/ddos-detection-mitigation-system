"""
Data Retention and Compliance Module

Handles GDPR, CCPA, and other data protection regulation compliance
for the DDoS detection system.
"""

import json
import logging
import hashlib
import os
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


class ComplianceRegulation(Enum):
    """Supported compliance regulations"""
    GDPR = "gdpr"
    CCPA = "ccpa"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    SOC2 = "soc2"


class DataCategory(Enum):
    """Categories of data for retention purposes"""
    RAW_PACKETS = "raw_packets"
    FLOWS = "flows"
    ALERTS = "alerts"
    METRICS = "metrics"
    AUDIT_LOGS = "audit_logs"
    ML_MODELS = "ml_models"
    CONFIGURATION = "configuration"


@dataclass
class RetentionPolicy:
    """Data retention policy for a data category"""
    category: DataCategory
    retention_days: int
    aggregation_enabled: bool = False
    aggregation_interval_days: int = 1
    delete_after_retention: bool = True
    archive_before_delete: bool = False
    archive_path: Optional[str] = None


@dataclass
class AuditEntry:
    """Audit log entry"""
    timestamp: datetime
    action: str
    user: Optional[str]
    resource: str
    details: Dict[str, Any]
    compliance_reason: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'timestamp': self.timestamp.isoformat(),
            'action': self.action,
            'user': self.user,
            'resource': self.resource,
            'details': self.details,
            'compliance_reason': self.compliance_reason,
        }


class DataStoreInterface:
    """Interface for data storage operations"""
    
    def delete_older_than(self, cutoff_date: datetime, category: Optional[DataCategory] = None) -> int:
        """Delete records older than cutoff date"""
        raise NotImplementedError
    
    def archive_older_than(self, cutoff_date: datetime, archive_path: str) -> int:
        """Archive records older than cutoff date"""
        raise NotImplementedError
    
    def get_count_older_than(self, cutoff_date: datetime) -> int:
        """Get count of records older than cutoff date"""
        raise NotImplementedError


class GDPRComplianceManager:
    """
    GDPR Compliance Manager for DDoS detection system.
    
    Handles:
    - Data retention policies
    - PII masking and pseudonymization
    - Right to erasure (deletion requests)
    - Audit logging
    - Data portability (export)
    """
    
    def __init__(
        self, 
        retention_days: int = 30, 
        pii_mask_enabled: bool = True,
        salt: Optional[str] = None,
        audit_log_path: str = "/app/logs/audit.log"
    ):
        self.retention_days = retention_days
        self.pii_mask_enabled = pii_mask_enabled
        self.salt = salt or os.environ.get("GDPR_SALT", "default_salt_change_me")
        self.audit_log_path = Path(audit_log_path)
        self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Custom retention policies per data category
        self.retention_policies: Dict[DataCategory, RetentionPolicy] = {
            DataCategory.RAW_PACKETS: RetentionPolicy(
                category=DataCategory.RAW_PACKETS,
                retention_days=1,  # Raw packets kept for only 1 day
                aggregation_enabled=True,
                aggregation_interval_days=1,
            ),
            DataCategory.FLOWS: RetentionPolicy(
                category=DataCategory.FLOWS,
                retention_days=retention_days,
                aggregation_enabled=False,
            ),
            DataCategory.ALERTS: RetentionPolicy(
                category=DataCategory.ALERTS,
                retention_days=90,  # Keep alerts longer for auditing
            ),
            DataCategory.METRICS: RetentionPolicy(
                category=DataCategory.METRICS,
                retention_days=retention_days,
                aggregation_enabled=True,
                aggregation_interval_days=1,
            ),
            DataCategory.AUDIT_LOGS: RetentionPolicy(
                category=DataCategory.AUDIT_LOGS,
                retention_days=365,  # Keep audit logs for 1 year
                archive_before_delete=True,
            ),
            DataCategory.ML_MODELS: RetentionPolicy(
                category=DataCategory.ML_MODELS,
                retention_days=0,  # Don't auto-delete models
                delete_after_retention=False,
            ),
            DataCategory.CONFIGURATION: RetentionPolicy(
                category=DataCategory.CONFIGURATION,
                retention_days=0,  # Don't auto-delete configs
                delete_after_retention=False,
            ),
        }
        
        logger.info(f"GDPRComplianceManager initialized: retention_days={retention_days}, "
                   f"pii_mask_enabled={pii_mask_enabled}")
    
    def pseudonymize_ip(self, ip_address: str, salt: Optional[str] = None) -> str:
        """
        GDPR-compliant IP pseudonymization (one-way hash with salt).
        
        This is compliant with GDPR Article 25 (Data Protection by Design)
        and Recital 30 (online identifiers).
        
        Args:
            ip_address: IP address to pseudonymize
            salt: Optional salt override
            
        Returns:
            Pseudonymized IP (hash digest)
        """
        if not self.pii_mask_enabled:
            return ip_address
        
        if not ip_address:
            return ""
        
        # Use provided salt or default
        salt_value = salt or self.salt
        
        # One-way hash with salt (GDPR compliant for analytics)
        hash_input = f"{ip_address}{salt_value}".encode('utf-8')
        
        # Blake2b is fast and cryptographically secure
        hash_digest = hashlib.blake2b(hash_input, digest_size=16).hexdigest()
        
        # Add prefix to indicate pseudonymized data
        return f"pseudonym:{hash_digest}"
    
    def pseudonymize_email(self, email: str) -> str:
        """Pseudonymize email address for GDPR compliance"""
        if not self.pii_mask_enabled or not email:
            return email
        
        local_part, domain = email.split('@') if '@' in email else (email, 'unknown')
        hash_local = hashlib.sha256(local_part.encode()).hexdigest()[:8]
        
        return f"user_{hash_local}@{domain}"
    
    def mask_sensitive_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Mask sensitive PII in data structures.
        
        Removes or masks fields like IP addresses, email, credit card numbers.
        
        Args:
            data: Dictionary containing potentially sensitive data
            
        Returns:
            Dictionary with masked sensitive fields
        """
        if not self.pii_mask_enabled:
            return data
        
        masked_data = data.copy()
        
        # List of sensitive field patterns
        sensitive_fields = [
            'ip_src', 'ip_dst', 'src_ip', 'dst_ip', 'source_ip', 'destination_ip',
            'email', 'user_email', 'customer_email',
            'credit_card', 'card_number', 'cc_number',
            'phone', 'phone_number', 'mobile',
            'ssn', 'social_security',
        ]
        
        for field in sensitive_fields:
            if field in masked_data and masked_data[field]:
                if 'ip' in field.lower():
                    masked_data[field] = self.pseudonymize_ip(str(masked_data[field]))
                elif 'email' in field.lower():
                    masked_data[field] = self.pseudonymize_email(str(masked_data[field]))
                else:
                    # Generic masking for other sensitive fields
                    masked_data[field] = "***MASKED***"
        
        return masked_data
    
    def apply_retention_policy(self, data_store: DataStoreInterface, 
                               category: Optional[DataCategory] = None) -> Dict[str, int]:
        """
        Apply retention policy to delete or archive old data.
        
        Args:
            data_store: Data store implementation
            category: Specific category to clean (None = all categories)
            
        Returns:
            Dictionary with deletion counts per category
        """
        results = {}
        
        categories = [category] if category else list(self.retention_policies.keys())
        
        for cat in categories:
            policy = self.retention_policies.get(cat)
            if not policy or policy.retention_days == 0:
                continue
            
            cutoff_date = datetime.now() - timedelta(days=policy.retention_days)
            
            # Check if we should archive before deletion
            if policy.archive_before_delete and policy.archive_path:
                archived_count = data_store.archive_older_than(cutoff_date, policy.archive_path)
                results[f"{cat.value}_archived"] = archived_count
                logger.info(f"Archived {archived_count} {cat.value} records to {policy.archive_path}")
            
            # Delete old records
            if policy.delete_after_retention:
                deleted_count = data_store.delete_older_than(cutoff_date, cat)
                results[f"{cat.value}_deleted"] = deleted_count
                logger.info(f"Deleted {deleted_count} {cat.value} records older than {cutoff_date}")
                
                # Log deletion for audit trail
                self._audit_deletion(
                    count=deleted_count, 
                    cutoff=cutoff_date,
                    category=cat,
                    policy=policy
                )
        
        return results
    
    def _audit_deletion(self, count: int, cutoff: datetime, 
                        category: DataCategory, policy: RetentionPolicy):
        """Maintain audit log of data deletions"""
        audit_entry = AuditEntry(
            timestamp=datetime.now(),
            action='data_retention_deletion',
            user='system',
            resource=f"data_store:{category.value}",
            details={
                'records_deleted': count,
                'cutoff_date': cutoff.isoformat(),
                'retention_days': policy.retention_days,
                'category': category.value,
                'archive_before_delete': policy.archive_before_delete,
            },
            compliance_reason='GDPR Article 17 (Right to erasure)'
        )
        self._write_audit_log(audit_entry)
    
    def handle_deletion_request(self, data_store: DataStoreInterface, 
                                identifier: str, 
                                identifier_type: str = 'ip') -> bool:
        """
        Handle GDPR Article 17 (Right to Erasure) request.
        
        Args:
            data_store: Data store implementation
            identifier: User identifier (IP, email, user ID)
            identifier_type: Type of identifier ('ip', 'email', 'user_id')
            
        Returns:
            True if deletion was successful
        """
        logger.info(f"Processing deletion request for {identifier_type}: {identifier}")
        
        try:
            # Pseudonymize the identifier for lookup
            if identifier_type == 'ip':
                pseudonymized = self.pseudonymize_ip(identifier)
            elif identifier_type == 'email':
                pseudonymized = self.pseudonymize_email(identifier)
            else:
                pseudonymized = identifier
            
            # Delete user data from all data stores
            deleted_records = data_store.delete_by_identifier(pseudonymized, identifier_type)
            
            # Audit the deletion
            audit_entry = AuditEntry(
                timestamp=datetime.now(),
                action='gdpr_deletion_request',
                user=identifier,
                resource='user_data',
                details={
                    'identifier_type': identifier_type,
                    'records_deleted': deleted_records,
                    'pseudonymized_identifier': pseudonymized,
                },
                compliance_reason='GDPR Article 17 - Right to erasure'
            )
            self._write_audit_log(audit_entry)
            
            logger.info(f"Deleted {deleted_records} records for {identifier_type}: {identifier}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to process deletion request: {e}")
            return False
    
    def export_user_data(self, data_store: DataStoreInterface,
                         identifier: str,
                         identifier_type: str = 'ip') -> Optional[Dict[str, Any]]:
        """
        Handle GDPR Article 20 (Right to Data Portability) request.
        
        Args:
            data_store: Data store implementation
            identifier: User identifier
            identifier_type: Type of identifier
            
        Returns:
            Dictionary containing user's data in structured format
        """
        logger.info(f"Processing data export request for {identifier_type}: {identifier}")
        
        try:
            # Pseudonymize identifier for lookup
            if identifier_type == 'ip':
                pseudonymized = self.pseudonymize_ip(identifier)
            else:
                pseudonymized = identifier
            
            # Fetch user data
            user_data = data_store.get_user_data(pseudonymized, identifier_type)
            
            # Audit the export
            audit_entry = AuditEntry(
                timestamp=datetime.now(),
                action='gdpr_data_export',
                user=identifier,
                resource='user_data',
                details={
                    'identifier_type': identifier_type,
                    'records_exported': len(user_data) if user_data else 0,
                },
                compliance_reason='GDPR Article 20 - Right to data portability'
            )
            self._write_audit_log(audit_entry)
            
            logger.info(f"Exported {len(user_data) if user_data else 0} records for {identifier}")
            return user_data
            
        except Exception as e:
            logger.error(f"Failed to export user data: {e}")
            return None
    
    def _write_audit_log(self, entry: AuditEntry):
        """Write audit entry to log file"""
        try:
            with open(self.audit_log_path, 'a') as f:
                f.write(json.dumps(entry.to_dict()) + '\n')
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")
    
    def get_audit_logs(self, start_date: Optional[datetime] = None, 
                       end_date: Optional[datetime] = None,
                       action: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve audit logs for compliance reporting"""
        logs = []
        
        if not self.audit_log_path.exists():
            return logs
        
        try:
            with open(self.audit_log_path, 'r') as f:
                for line in f:
                    if line.strip():
                        entry = json.loads(line)
                        entry_time = datetime.fromisoformat(entry['timestamp'])
                        
                        # Apply filters
                        if start_date and entry_time < start_date:
                            continue
                        if end_date and entry_time > end_date:
                            continue
                        if action and entry['action'] != action:
                            continue
                        
                        logs.append(entry)
        except Exception as e:
            logger.error(f"Failed to read audit logs: {e}")
        
        return logs
    
    def get_compliance_report(self) -> Dict[str, Any]:
        """Generate compliance report for auditors"""
        return {
            'regulation': 'GDPR',
            'compliance_date': datetime.now().isoformat(),
            'retention_policies': {
                cat.value: {
                    'retention_days': policy.retention_days,
                    'delete_after_retention': policy.delete_after_retention,
                    'archive_before_delete': policy.archive_before_delete,
                }
                for cat, policy in self.retention_policies.items()
            },
            'pii_masking_enabled': self.pii_mask_enabled,
            'audit_log_size': self.audit_log_path.stat().st_size if self.audit_log_path.exists() else 0,
            'audit_log_entries': len(self.get_audit_logs()),
            'retention_days_default': self.retention_days,
        }


class SimpleDataStore(DataStoreInterface):
    """Simple in-memory data store implementation for testing"""
    
    def __init__(self):
        self.data: List[Dict[str, Any]] = []
        self.timestamp_field = 'timestamp'
    
    def add_record(self, record: Dict[str, Any]):
        """Add a record to the store"""
        self.data.append(record)
    
    def delete_older_than(self, cutoff_date: datetime, category: Optional[DataCategory] = None) -> int:
        """Delete records older than cutoff date"""
        original_count = len(self.data)
        self.data = [
            record for record in self.data
            if datetime.fromisoformat(record.get(self.timestamp_field, datetime.now().isoformat())) >= cutoff_date
        ]
        return original_count - len(self.data)
    
    def archive_older_than(self, cutoff_date: datetime, archive_path: str) -> int:
        """Archive records older than cutoff date"""
        old_records = [
            record for record in self.data
            if datetime.fromisoformat(record.get(self.timestamp_field, datetime.now().isoformat())) < cutoff_date
        ]
        
        # Write to archive file
        archive_file = Path(archive_path) / f"archive_{cutoff_date.strftime('%Y%m%d')}.json"
        archive_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(archive_file, 'w') as f:
            json.dump(old_records, f)
        
        return len(old_records)
    
    def delete_by_identifier(self, identifier: str, identifier_type: str) -> int:
        """Delete records by identifier"""
        original_count = len(self.data)
        self.data = [
            record for record in self.data
            if record.get(identifier_type) != identifier
        ]
        return original_count - len(self.data)
    
    def get_user_data(self, identifier: str, identifier_type: str) -> Dict[str, Any]:
        """Get user data for export"""
        user_records = [
            record for record in self.data
            if record.get(identifier_type) == identifier
        ]
        return {'records': user_records, 'export_date': datetime.now().isoformat()}
    
    def get_count_older_than(self, cutoff_date: datetime) -> int:
        """Get count of records older than cutoff date"""
        return sum(1 for record in self.data
                  if datetime.fromisoformat(record.get(self.timestamp_field, datetime.now().isoformat())) < cutoff_date)


# Convenience function for quick setup
def create_compliance_manager(retention_days: int = 30) -> GDPRComplianceManager:
    """Create a configured GDPR compliance manager"""
    salt = os.environ.get("GDPR_SALT", None)
    pii_masking = os.environ.get("ENABLE_PII_MASKING", "true").lower() == "true"
    
    return GDPRComplianceManager(
        retention_days=retention_days,
        pii_mask_enabled=pii_masking,
        salt=salt
    )