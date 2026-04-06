"""
Data Retention and Compliance Module

Handles GDPR, CCPA, and other data-protection regulation compliance
for the DDoS detection system.
"""

import hashlib
import json
import logging
import os
import secrets
import threading
from dataclasses import dataclass, field as dc_field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class ComplianceRegulation(Enum):
    GDPR = "gdpr"
    CCPA = "ccpa"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    SOC2 = "soc2"


class DataCategory(Enum):
    RAW_PACKETS = "raw_packets"
    FLOWS = "flows"
    ALERTS = "alerts"
    METRICS = "metrics"
    AUDIT_LOGS = "audit_logs"
    ML_MODELS = "ml_models"
    CONFIGURATION = "configuration"


@dataclass
class RetentionPolicy:
    category: DataCategory
    retention_days: int
    aggregation_enabled: bool = False
    aggregation_interval_days: int = 1
    delete_after_retention: bool = True
    archive_before_delete: bool = False
    archive_path: Optional[str] = None


@dataclass
class AuditEntry:
    timestamp: datetime
    action: str
    user: Optional[str]
    resource: str
    details: Dict[str, Any]
    compliance_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp.isoformat(),
            'action': self.action,
            'user': self.user,
            'resource': self.resource,
            'details': self.details,
            'compliance_reason': self.compliance_reason,
        }


class DataStoreInterface:
    """Interface for data storage operations."""

    def delete_older_than(
        self,
        cutoff_date: datetime,
        category: Optional[DataCategory] = None,
    ) -> int:
        raise NotImplementedError

    def archive_older_than(self, cutoff_date: datetime, archive_path: str) -> int:
        raise NotImplementedError

    def get_count_older_than(self, cutoff_date: datetime) -> int:
        raise NotImplementedError

    # FIX BUG-34 / BUG-35: These methods are called by GDPRComplianceManager
    # but were absent from the interface.  SimpleDataStore implemented them,
    # but callers working against the interface had no declared contract.
    def delete_by_identifier(self, identifier: str, identifier_type: str) -> int:
        raise NotImplementedError

    def get_user_data(self, identifier: str, identifier_type: str) -> Dict[str, Any]:
        raise NotImplementedError


class GDPRComplianceManager:
    """
    GDPR Compliance Manager for the DDoS detection system.

    Handles:
    - Data retention policies (Article 5(1)(e))
    - PII pseudonymisation (Article 25 / Recital 30)
    - Right to erasure (Article 17)
    - Audit logging
    - Data portability (Article 20)
    """

    def __init__(
        self,
        retention_days: int = 30,
        pii_mask_enabled: bool = True,
        salt: Optional[str] = None,
        audit_log_path: str = "/app/logs/audit.log",
    ) -> None:
        self.retention_days = retention_days
        self.pii_mask_enabled = pii_mask_enabled

        # FIX BUG-38: A hardcoded fallback salt ("default_salt_change_me")
        # means all deployments share the same salt, making pseudonyms
        # trivially reversible via dictionary attack across installations.
        # Now we generate a cryptographically random salt per-instance and
        # emit a loud warning so operators know to persist it externally.
        env_salt = os.environ.get("GDPR_SALT")
        if salt:
            self.salt = salt
        elif env_salt:
            self.salt = env_salt
        else:
            self.salt = secrets.token_hex(32)
            logger.warning(
                "GDPR_SALT environment variable is not set. A random ephemeral "
                "salt has been generated.  Pseudonyms will NOT be consistent "
                "across process restarts.  Set GDPR_SALT for production use."
            )

        self.audit_log_path = Path(audit_log_path)
        self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
        # FIX BUG-36: Lock protects concurrent audit-log writes from multiple
        # threads / asyncio worker threads so JSON-lines records are never
        # interleaved or partially written.
        self._audit_lock = threading.Lock()

        self.retention_policies: Dict[DataCategory, RetentionPolicy] = {
            DataCategory.RAW_PACKETS: RetentionPolicy(
                category=DataCategory.RAW_PACKETS,
                retention_days=1,
                aggregation_enabled=True,
                aggregation_interval_days=1,
            ),
            DataCategory.FLOWS: RetentionPolicy(
                category=DataCategory.FLOWS,
                retention_days=retention_days,
            ),
            DataCategory.ALERTS: RetentionPolicy(
                category=DataCategory.ALERTS,
                retention_days=90,
            ),
            DataCategory.METRICS: RetentionPolicy(
                category=DataCategory.METRICS,
                retention_days=retention_days,
                aggregation_enabled=True,
                aggregation_interval_days=1,
            ),
            DataCategory.AUDIT_LOGS: RetentionPolicy(
                category=DataCategory.AUDIT_LOGS,
                retention_days=365,
                archive_before_delete=True,
            ),
            DataCategory.ML_MODELS: RetentionPolicy(
                category=DataCategory.ML_MODELS,
                retention_days=0,
                delete_after_retention=False,
            ),
            DataCategory.CONFIGURATION: RetentionPolicy(
                category=DataCategory.CONFIGURATION,
                retention_days=0,
                delete_after_retention=False,
            ),
        }

        logger.info(
            f"GDPRComplianceManager initialised: retention_days={retention_days}, "
            f"pii_mask_enabled={pii_mask_enabled}"
        )

    # ------------------------------------------------------------------
    # Pseudonymisation
    # ------------------------------------------------------------------

    def pseudonymize_ip(self, ip_address: str, salt: Optional[str] = None) -> str:
        """
        GDPR-compliant IP pseudonymisation via one-way salted hash.

        Compliant with GDPR Article 25 (Data Protection by Design) and
        Recital 30 (online identifiers as personal data).
        """
        if not self.pii_mask_enabled:
            return ip_address
        if not ip_address:
            return ""

        salt_value = salt or self.salt
        raw = f"{ip_address}{salt_value}".encode("utf-8")
        digest = hashlib.blake2b(raw, digest_size=16).hexdigest()
        return f"pseudonym:{digest}"

    def pseudonymize_email(self, email: str) -> str:
        """
        Pseudonymise an email address.

        FIX BUG-33: The original hash used no salt, making common local-parts
        (admin, user, info) trivially reversible via dictionary attack.
        Now uses the same instance salt as pseudonymize_ip().
        """
        if not self.pii_mask_enabled or not email:
            return email

        local_part, domain = email.split("@") if "@" in email else (email, "unknown")
        # FIX BUG-33: include salt in the hash input.
        raw = f"{local_part}{self.salt}".encode("utf-8")
        hash_local = hashlib.sha256(raw).hexdigest()[:8]
        return f"user_{hash_local}@{domain}"

    def mask_sensitive_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Mask / pseudonymise PII fields in a data dictionary."""
        if not self.pii_mask_enabled:
            return data

        masked_data = data.copy()

        sensitive_fields = [
            "ip_src", "ip_dst", "src_ip", "dst_ip", "source_ip", "destination_ip",
            "email", "user_email", "customer_email",
            "credit_card", "card_number", "cc_number",
            "phone", "phone_number", "mobile",
            "ssn", "social_security",
        ]

        # FIX BUG-37: Loop variable renamed from 'field' (which shadows the
        # dataclasses.field import) to 'field_name'.
        for field_name in sensitive_fields:
            if field_name in masked_data and masked_data[field_name]:
                if "ip" in field_name.lower():
                    masked_data[field_name] = self.pseudonymize_ip(
                        str(masked_data[field_name])
                    )
                elif "email" in field_name.lower():
                    masked_data[field_name] = self.pseudonymize_email(
                        str(masked_data[field_name])
                    )
                else:
                    masked_data[field_name] = "***MASKED***"

        return masked_data

    # ------------------------------------------------------------------
    # Retention policy enforcement
    # ------------------------------------------------------------------

    def apply_retention_policy(
        self,
        data_store: DataStoreInterface,
        category: Optional[DataCategory] = None,
    ) -> Dict[str, int]:
        results: Dict[str, int] = {}
        categories = [category] if category else list(self.retention_policies.keys())

        for cat in categories:
            policy = self.retention_policies.get(cat)
            if not policy or policy.retention_days == 0:
                continue

            cutoff = datetime.now() - timedelta(days=policy.retention_days)

            if policy.archive_before_delete and policy.archive_path:
                archived = data_store.archive_older_than(cutoff, policy.archive_path)
                results[f"{cat.value}_archived"] = archived
                logger.info(
                    f"Archived {archived} {cat.value} records to {policy.archive_path}"
                )

            if policy.delete_after_retention:
                deleted = data_store.delete_older_than(cutoff, cat)
                results[f"{cat.value}_deleted"] = deleted
                logger.info(
                    f"Deleted {deleted} {cat.value} records older than {cutoff}"
                )
                self._audit_deletion(
                    count=deleted, cutoff=cutoff, category=cat, policy=policy
                )

        return results

    def _audit_deletion(
        self,
        count: int,
        cutoff: datetime,
        category: DataCategory,
        policy: RetentionPolicy,
    ) -> None:
        entry = AuditEntry(
            timestamp=datetime.now(),
            action="data_retention_deletion",
            user="system",
            resource=f"data_store:{category.value}",
            details={
                "records_deleted": count,
                "cutoff_date": cutoff.isoformat(),
                "retention_days": policy.retention_days,
                "category": category.value,
                "archive_before_delete": policy.archive_before_delete,
            },
            compliance_reason="GDPR Article 17 (Right to erasure)",
        )
        self._write_audit_log(entry)

    # ------------------------------------------------------------------
    # Right to erasure (Article 17)
    # ------------------------------------------------------------------

    def handle_deletion_request(
        self,
        data_store: DataStoreInterface,
        identifier: str,
        identifier_type: str = "ip",
    ) -> bool:
        logger.info(f"Processing deletion request for {identifier_type}")
        try:
            if identifier_type == "ip":
                pseudonymised = self.pseudonymize_ip(identifier)
            elif identifier_type == "email":
                pseudonymised = self.pseudonymize_email(identifier)
            else:
                pseudonymised = identifier

            deleted = data_store.delete_by_identifier(pseudonymised, identifier_type)

            self._write_audit_log(
                AuditEntry(
                    timestamp=datetime.now(),
                    action="gdpr_deletion_request",
                    user=identifier,
                    resource="user_data",
                    details={
                        "identifier_type": identifier_type,
                        "records_deleted": deleted,
                        "pseudonymised_identifier": pseudonymised,
                    },
                    compliance_reason="GDPR Article 17 - Right to erasure",
                )
            )
            logger.info(f"Deleted {deleted} records for {identifier_type}")
            return True

        except Exception as exc:
            logger.error(f"Failed to process deletion request: {exc}")
            return False

    # ------------------------------------------------------------------
    # Right to data portability (Article 20)
    # ------------------------------------------------------------------

    def export_user_data(
        self,
        data_store: DataStoreInterface,
        identifier: str,
        identifier_type: str = "ip",
    ) -> Optional[Dict[str, Any]]:
        logger.info(f"Processing data export for {identifier_type}")
        try:
            pseudonymised = (
                self.pseudonymize_ip(identifier)
                if identifier_type == "ip"
                else identifier
            )
            user_data = data_store.get_user_data(pseudonymised, identifier_type)

            self._write_audit_log(
                AuditEntry(
                    timestamp=datetime.now(),
                    action="gdpr_data_export",
                    user=identifier,
                    resource="user_data",
                    details={
                        "identifier_type": identifier_type,
                        "records_exported": len(user_data) if user_data else 0,
                    },
                    compliance_reason="GDPR Article 20 - Right to data portability",
                )
            )
            logger.info(
                f"Exported {len(user_data) if user_data else 0} records"
            )
            return user_data

        except Exception as exc:
            logger.error(f"Failed to export user data: {exc}")
            return None

    # ------------------------------------------------------------------
    # Audit log
    # ------------------------------------------------------------------

    def _write_audit_log(self, entry: AuditEntry) -> None:
        """
        Append an audit entry to the log file.

        FIX BUG-36: File writes are protected by a threading.Lock() so
        concurrent calls from multiple threads cannot interleave partial
        writes and corrupt the JSON-lines format.
        """
        try:
            with self._audit_lock:  # FIX BUG-36
                with open(self.audit_log_path, "a") as fh:
                    fh.write(json.dumps(entry.to_dict()) + "\n")
        except Exception as exc:
            logger.error(f"Failed to write audit log: {exc}")

    def get_audit_logs(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        action: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        logs: List[Dict[str, Any]] = []
        if not self.audit_log_path.exists():
            return logs
        try:
            with open(self.audit_log_path, "r") as fh:
                for line in fh:
                    if not line.strip():
                        continue
                    entry = json.loads(line)
                    ts = datetime.fromisoformat(entry["timestamp"])
                    if start_date and ts < start_date:
                        continue
                    if end_date and ts > end_date:
                        continue
                    if action and entry["action"] != action:
                        continue
                    logs.append(entry)
        except Exception as exc:
            logger.error(f"Failed to read audit logs: {exc}")
        return logs

    def get_compliance_report(self) -> Dict[str, Any]:
        return {
            "regulation": "GDPR",
            "compliance_date": datetime.now().isoformat(),
            "retention_policies": {
                cat.value: {
                    "retention_days": p.retention_days,
                    "delete_after_retention": p.delete_after_retention,
                    "archive_before_delete": p.archive_before_delete,
                }
                for cat, p in self.retention_policies.items()
            },
            "pii_masking_enabled": self.pii_mask_enabled,
            "audit_log_size": (
                self.audit_log_path.stat().st_size
                if self.audit_log_path.exists()
                else 0
            ),
            "audit_log_entries": len(self.get_audit_logs()),
            "retention_days_default": self.retention_days,
        }


class SimpleDataStore(DataStoreInterface):
    """Simple in-memory data store (for testing and development)."""

    def __init__(self) -> None:
        self.data: List[Dict[str, Any]] = []
        self.timestamp_field = "timestamp"

    def _parse_ts(self, record: Dict[str, Any]) -> datetime:
        """
        Parse the record's timestamp safely.

        FIX BUG-39: The original code defaulted missing timestamps to
        datetime.now(), so records with no timestamp were always treated as
        "current" and never deleted.  Now we default to datetime.min so
        timestamp-less records are always considered expired.
        """
        raw = record.get(self.timestamp_field)
        if not raw:
            return datetime.min   # FIX BUG-39
        try:
            return datetime.fromisoformat(str(raw))
        except ValueError:
            return datetime.min   # FIX BUG-39: malformed → treat as oldest

    def add_record(self, record: Dict[str, Any]) -> None:
        self.data.append(record)

    def delete_older_than(
        self,
        cutoff_date: datetime,
        category: Optional[DataCategory] = None,
    ) -> int:
        original = len(self.data)
        self.data = [r for r in self.data if self._parse_ts(r) >= cutoff_date]
        return original - len(self.data)

    def archive_older_than(self, cutoff_date: datetime, archive_path: str) -> int:
        old = [r for r in self.data if self._parse_ts(r) < cutoff_date]
        archive_file = (
            Path(archive_path) / f"archive_{cutoff_date.strftime('%Y%m%d')}.json"
        )
        archive_file.parent.mkdir(parents=True, exist_ok=True)
        with open(archive_file, "w") as fh:
            json.dump(old, fh)
        return len(old)

    def delete_by_identifier(self, identifier: str, identifier_type: str) -> int:
        original = len(self.data)
        self.data = [r for r in self.data if r.get(identifier_type) != identifier]
        return original - len(self.data)

    def get_user_data(self, identifier: str, identifier_type: str) -> Dict[str, Any]:
        records = [r for r in self.data if r.get(identifier_type) == identifier]
        return {"records": records, "export_date": datetime.now().isoformat()}

    def get_count_older_than(self, cutoff_date: datetime) -> int:
        return sum(1 for r in self.data if self._parse_ts(r) < cutoff_date)


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------

def create_compliance_manager(retention_days: int = 30) -> GDPRComplianceManager:
    """Create a configured GDPR compliance manager from environment variables."""
    salt = os.environ.get("GDPR_SALT")
    pii_masking = os.environ.get("ENABLE_PII_MASKING", "true").lower() == "true"
    return GDPRComplianceManager(
        retention_days=retention_days,
        pii_mask_enabled=pii_masking,
        salt=salt,
    )