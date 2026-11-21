"""Tamper-Evident SHA-256 Hash-Chained DPDP Audit Ledger.

Implements an append-only, zero-PII audit ledger for the Sovereign Agentic
Context Protocol (SACP) compliant with the Digital Personal Data Protection (DPDP) Act, 2023.
Supports SQLite (default) and PostgreSQL (via DATABASE_URL).
"""

from datetime import datetime, timezone
import hashlib
import json
import os
import sqlite3
import threading
from typing import Any, Dict, List, Optional, Tuple, Union

GENESIS_PREV_HASH = "GENESIS_0000000000000000"


class DPDPAuditLedger:
    """Append-only, SHA-256 hash-chained audit ledger guaranteeing zero PII storage."""

    def __init__(self, db_url: Optional[str] = None) -> None:
        """Initialize DPDPAuditLedger.

        Args:
            db_url: SQLite path/URL (e.g. 'sqlite:///./sacp_audit.db', ':memory:')
                    or PostgreSQL URL (e.g. 'postgresql://...'). Defaults to env
                    DATABASE_URL or 'sqlite:///./sacp_audit.db'.
        """
        raw_url = db_url or os.getenv("DATABASE_URL") or "sqlite:///./sacp_audit.db"
        self.db_url = raw_url
        self._lock = threading.Lock()
        self._is_postgres = raw_url.startswith("postgres://") or raw_url.startswith("postgresql://")

        if self._is_postgres:
            self._init_postgres(raw_url)
        else:
            self._init_sqlite(raw_url)

    def _init_sqlite(self, url: str) -> None:
        """Initialize SQLite database schema and connection."""
        clean_path = url.replace("sqlite:///", "").replace("sqlite://", "")
        self.sqlite_path = clean_path
        self._conn = sqlite3.connect(clean_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._create_sqlite_tables(self._conn)

    def _create_sqlite_tables(self, conn: sqlite3.Connection) -> None:
        """Create tables and indexes on SQLite connection."""
        with self._lock:
            with conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS dpdp_audit_ledger (
                        seq_id INTEGER PRIMARY KEY,
                        timestamp_utc TEXT NOT NULL,
                        consent_id TEXT NOT NULL,
                        txnid TEXT NOT NULL,
                        agent_id TEXT NOT NULL,
                        requested_purpose_code TEXT NOT NULL,
                        requested_fi_type TEXT NOT NULL,
                        decision TEXT NOT NULL,
                        reason TEXT NOT NULL,
                        output_sha256 TEXT NOT NULL,
                        prev_hash TEXT NOT NULL,
                        entry_hash TEXT NOT NULL
                    )
                    """
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_audit_consent_id ON dpdp_audit_ledger(consent_id)"
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON dpdp_audit_ledger(timestamp_utc)"
                )

    def _get_sqlite_conn(self) -> sqlite3.Connection:
        """Get an active SQLite connection, reopening if necessary."""
        try:
            self._conn.execute("SELECT 1")
            return self._conn
        except (sqlite3.ProgrammingError, AttributeError):
            self._conn = sqlite3.connect(self.sqlite_path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._create_sqlite_tables(self._conn)
            return self._conn

    def _init_postgres(self, url: str) -> None:
        """Initialize PostgreSQL connection if psycopg/psycopg2 is available, otherwise fallback."""
        try:
            import psycopg

            self._pg_conn = psycopg.connect(url, autocommit=True)
            with self._lock:
                with self._pg_conn.cursor() as cur:
                    cur.execute(
                        """
                        CREATE TABLE IF NOT EXISTS dpdp_audit_ledger (
                            seq_id BIGINT PRIMARY KEY,
                            timestamp_utc TEXT NOT NULL,
                            consent_id TEXT NOT NULL,
                            txnid TEXT NOT NULL,
                            agent_id TEXT NOT NULL,
                            requested_purpose_code TEXT NOT NULL,
                            requested_fi_type TEXT NOT NULL,
                            decision TEXT NOT NULL,
                            reason TEXT NOT NULL,
                            output_sha256 TEXT NOT NULL,
                            prev_hash TEXT NOT NULL,
                            entry_hash TEXT NOT NULL
                        );
                        CREATE INDEX IF NOT EXISTS idx_audit_consent_id ON dpdp_audit_ledger(consent_id);
                        CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON dpdp_audit_ledger(timestamp_utc);
                        """
                    )
        except Exception:
            # Fallback to local SQLite if PostgreSQL driver is unavailable
            self._is_postgres = False
            self._init_sqlite("sqlite:///./sacp_audit.db")

    @staticmethod
    def compute_entry_hash(payload: Dict[str, Any]) -> str:
        """Compute deterministic SHA-256 hex digest over canonical JSON representation."""
        canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

    def record_event(
        self,
        consent_id: str,
        txnid: str,
        requested_purpose_code: str,
        decision: str,
        reason: str,
        requested_fi_type: str = "DEPOSIT",
        agent_id: str = "unknown-mcp-client",
        output_sha256: str = "NONE",
        timestamp_utc: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Record an immutable, hash-chained audit event.

        Args:
            consent_id: Consent UUID.
            txnid: Transaction identifier.
            requested_purpose_code: Purpose code (e.g. '101').
            decision: 'AUTHORIZED' or 'DENIED'.
            reason: Reason or status code.
            requested_fi_type: FI type (e.g. 'DEPOSIT').
            agent_id: Client identifier.
            output_sha256: SHA-256 of derived response or 'NONE'.
            timestamp_utc: Optional ISO-8601 UTC timestamp.

        Returns:
            dict: Signed receipt containing seq_id, entry_hash, and timestamp_utc.
        """
        now_utc = timestamp_utc or datetime.now(timezone.utc).isoformat()

        with self._lock:
            # 1. Determine next seq_id and prev_hash
            if self._is_postgres:
                with self._pg_conn.cursor() as cur:
                    cur.execute(
                        "SELECT seq_id, entry_hash FROM dpdp_audit_ledger ORDER BY seq_id DESC LIMIT 1"
                    )
                    row = cur.fetchone()
            else:
                conn = self._get_sqlite_conn()
                cur = conn.execute(
                    "SELECT seq_id, entry_hash FROM dpdp_audit_ledger ORDER BY seq_id DESC LIMIT 1"
                )
                row = cur.fetchone()

            if row is None:
                seq_id = 1
                prev_hash = GENESIS_PREV_HASH
            else:
                seq_id = int(row[0]) + 1
                prev_hash = str(row[1])

            # 2. Build canonical payload for hash computation
            hash_payload = {
                "seq_id": seq_id,
                "timestamp_utc": now_utc,
                "consent_id": str(consent_id),
                "txnid": str(txnid),
                "agent_id": str(agent_id),
                "requested_purpose_code": str(requested_purpose_code),
                "requested_fi_type": str(requested_fi_type),
                "decision": str(decision),
                "reason": str(reason),
                "output_sha256": str(output_sha256),
                "prev_hash": prev_hash,
            }
            entry_hash = self.compute_entry_hash(hash_payload)

            # 3. Insert record into ledger
            if self._is_postgres:
                with self._pg_conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO dpdp_audit_ledger (
                            seq_id, timestamp_utc, consent_id, txnid, agent_id,
                            requested_purpose_code, requested_fi_type, decision, reason,
                            output_sha256, prev_hash, entry_hash
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """,
                        (
                            seq_id,
                            now_utc,
                            str(consent_id),
                            str(txnid),
                            str(agent_id),
                            str(requested_purpose_code),
                            str(requested_fi_type),
                            str(decision),
                            str(reason),
                            str(output_sha256),
                            prev_hash,
                            entry_hash,
                        ),
                    )
            else:
                conn = self._get_sqlite_conn()
                with conn:
                    conn.execute(
                        """
                        INSERT INTO dpdp_audit_ledger (
                            seq_id, timestamp_utc, consent_id, txnid, agent_id,
                            requested_purpose_code, requested_fi_type, decision, reason,
                            output_sha256, prev_hash, entry_hash
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            seq_id,
                            now_utc,
                            str(consent_id),
                            str(txnid),
                            str(agent_id),
                            str(requested_purpose_code),
                            str(requested_fi_type),
                            str(decision),
                            str(reason),
                            str(output_sha256),
                            prev_hash,
                            entry_hash,
                        ),
                    )

            return {
                "seq_id": seq_id,
                "entry_hash": entry_hash,
                "prev_hash": prev_hash,
                "timestamp_utc": now_utc,
                "decision": decision,
            }

    def verify_chain_integrity(self) -> Tuple[bool, str]:
        """Verify the cryptographic integrity of the entire audit chain from genesis to head.

        Validates:
        1. Monotonic sequence continuity (seq_k == seq_k-1 + 1, starting at 1).
        2. Cryptographic pointer continuity (prev_hash_k == entry_hash_k-1).
        3. Row content hash integrity (recomputed SHA-256 matches stored entry_hash).

        Returns:
            tuple[bool, str]: (True, success_msg) or (False, tamper_detail_msg).
        """
        with self._lock:
            if self._is_postgres:
                with self._pg_conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT seq_id, timestamp_utc, consent_id, txnid, agent_id,
                               requested_purpose_code, requested_fi_type, decision, reason,
                               output_sha256, prev_hash, entry_hash
                        FROM dpdp_audit_ledger
                        ORDER BY seq_id ASC
                        """
                    )
                    rows = cur.fetchall()
            else:
                conn = self._get_sqlite_conn()
                cur = conn.execute(
                    """
                    SELECT seq_id, timestamp_utc, consent_id, txnid, agent_id,
                           requested_purpose_code, requested_fi_type, decision, reason,
                           output_sha256, prev_hash, entry_hash
                    FROM dpdp_audit_ledger
                    ORDER BY seq_id ASC
                    """
                )
                rows = cur.fetchall()

        if not rows:
            return True, "Audit ledger is empty (genesis state)."

        expected_seq_id = 1
        expected_prev_hash = GENESIS_PREV_HASH

        for idx, row in enumerate(rows):
            seq_id = int(row[0])
            timestamp_utc = str(row[1])
            consent_id = str(row[2])
            txnid = str(row[3])
            agent_id = str(row[4])
            requested_purpose_code = str(row[5])
            requested_fi_type = str(row[6])
            decision = str(row[7])
            reason = str(row[8])
            output_sha256 = str(row[9])
            prev_hash = str(row[10])
            stored_entry_hash = str(row[11])

            # 1. Monotonic sequence continuity check (detects row deletion / insertion)
            if seq_id != expected_seq_id:
                return (
                    False,
                    f"Tamper detected: sequence break at index {idx + 1}. Expected seq_id {expected_seq_id}, found {seq_id}.",
                )

            # 2. Cryptographic pointer continuity check (detects row deletion / reordering)
            if prev_hash != expected_prev_hash:
                return (
                    False,
                    f"Tamper detected: broken hash link at seq_id {seq_id}. "
                    f"Expected prev_hash '{expected_prev_hash}', found '{prev_hash}'.",
                )

            # 3. Content digest verification (detects row modification / in-place tampering)
            expected_payload = {
                "seq_id": seq_id,
                "timestamp_utc": timestamp_utc,
                "consent_id": consent_id,
                "txnid": txnid,
                "agent_id": agent_id,
                "requested_purpose_code": requested_purpose_code,
                "requested_fi_type": requested_fi_type,
                "decision": decision,
                "reason": reason,
                "output_sha256": output_sha256,
                "prev_hash": prev_hash,
            }
            computed_hash = self.compute_entry_hash(expected_payload)

            if computed_hash != stored_entry_hash:
                return (
                    False,
                    f"Tamper detected: content hash mismatch at seq_id {seq_id}. "
                    f"Computed '{computed_hash}', stored '{stored_entry_hash}'.",
                )

            # Advance expected state
            expected_seq_id += 1
            expected_prev_hash = stored_entry_hash

        return True, f"Chain integrity verified across {len(rows)} entries."

    def count_entries(self) -> int:
        """Return total number of records in the audit ledger."""
        with self._lock:
            if self._is_postgres:
                with self._pg_conn.cursor() as cur:
                    cur.execute("SELECT COUNT(*) FROM dpdp_audit_ledger")
                    return int(cur.fetchone()[0])
            else:
                conn = self._get_sqlite_conn()
                cur = conn.execute("SELECT COUNT(*) FROM dpdp_audit_ledger")
                return int(cur.fetchone()[0])

    def close(self) -> None:
        """Close database connections."""
        with self._lock:
            if self._is_postgres and hasattr(self, "_pg_conn"):
                try:
                    self._pg_conn.close()
                except Exception:
                    pass
            elif hasattr(self, "_conn"):
                try:
                    self._conn.close()
                except Exception:
                    pass
