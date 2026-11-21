"""Pytest Test Suite for Phase 3: Tamper-Evident SHA-256 Hash-Chained DPDP Audit Ledger.

Tests:
1. Append multiple AUTHORIZED and DENIED events and assert verify_chain_integrity() passes.
2. Tamper detection: raw SQL UPDATE on row 2 of a 4-row chain detects exact tampered seq_id.
3. Row deletion detection: raw SQL DELETE on row 2 detects broken sequence/hash link.
4. End-to-end MCP execution (query_consented_financial_context + verify_sovereign_audit_trail)
   verifying audit receipts and asserting zero customer PII (Aarav Sharma, ABCDE1234F, 9988776655)
   ever enters the audit ledger database.
"""

import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt

from app.core.ephemeral_compute import encrypt_fi_payload_fernet
from app.ledger.audit_ledger import DPDPAuditLedger, GENESIS_PREV_HASH
from app.mcp_server.server import (
    query_consented_financial_context,
    set_audit_ledger,
    verify_sovereign_audit_trail,
)
from app.models.rebit_schema import (
    ConsentDetail,
    ConsentMode,
    ConsentStatus,
    CustomerIdentifier,
    FetchType,
    FIType,
    PartyIdentifier,
    PurposeDetail,
    RebitConsentArtefact,
)


@pytest.fixture(autouse=True)
def restore_mcp_ledger():
    """Ensure MCP server audit ledger is restored after tests."""
    yield
    set_audit_ledger(DPDPAuditLedger("sqlite:///:memory:"))


@pytest.fixture
def memory_ledger() -> DPDPAuditLedger:
    """Create an isolated in-memory DPDPAuditLedger instance."""
    ledger = DPDPAuditLedger("sqlite:///:memory:")
    yield ledger
    ledger.close()


def test_ledger_append_multiple_events_and_verify_chain(memory_ledger: DPDPAuditLedger):
    """Test 1: Append multiple AUTHORIZED and DENIED events; assert verify_chain_integrity passes."""
    events = [
        {
            "consent_id": "consent-001",
            "txnid": "txn-001",
            "requested_purpose_code": "101",
            "requested_fi_type": "DEPOSIT",
            "decision": "AUTHORIZED",
            "reason": "CONSENT_VERIFIED_EPHEMERAL_COMPUTED",
            "agent_id": "underwriting-agent-1",
            "output_sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        },
        {
            "consent_id": "consent-002",
            "txnid": "txn-002",
            "requested_purpose_code": "999",
            "requested_fi_type": "DEPOSIT",
            "decision": "DENIED",
            "reason": "DENIED_PURPOSE_MISMATCH",
            "agent_id": "risk-agent-2",
            "output_sha256": "NONE",
        },
        {
            "consent_id": "consent-003",
            "txnid": "txn-003",
            "requested_purpose_code": "101",
            "requested_fi_type": "CREDIT_CARD",
            "decision": "DENIED",
            "reason": "DENIED_FI_TYPE_UNAUTHORIZED",
            "agent_id": "card-agent-3",
            "output_sha256": "NONE",
        },
        {
            "consent_id": "consent-004",
            "txnid": "txn-004",
            "requested_purpose_code": "101",
            "requested_fi_type": "DEPOSIT",
            "decision": "AUTHORIZED",
            "reason": "CONSENT_VERIFIED_EPHEMERAL_COMPUTED",
            "agent_id": "underwriting-agent-1",
            "output_sha256": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        },
        {
            "consent_id": "consent-005",
            "txnid": "txn-005",
            "requested_purpose_code": "101",
            "requested_fi_type": "DEPOSIT",
            "decision": "DENIED",
            "reason": "DENIED_STORE_MODE_BLOCKED",
            "agent_id": "storage-agent-4",
            "output_sha256": "NONE",
        },
    ]

    receipts = []
    for ev in events:
        receipt = memory_ledger.record_event(**ev)
        receipts.append(receipt)

    assert len(receipts) == 5
    assert receipts[0]["seq_id"] == 1
    assert receipts[0]["prev_hash"] == GENESIS_PREV_HASH
    assert receipts[1]["seq_id"] == 2
    assert receipts[1]["prev_hash"] == receipts[0]["entry_hash"]
    assert receipts[4]["seq_id"] == 5

    assert memory_ledger.count_entries() == 5

    is_valid, msg = memory_ledger.verify_chain_integrity()
    assert is_valid is True
    assert "verified across 5 entries" in msg


def test_tamper_detection_via_sql_update(memory_ledger: DPDPAuditLedger):
    """Test 2: Raw SQL UPDATE on row 2 of a 4-row chain detects exact tampered seq_id."""
    # Append 4 valid events
    for i in range(1, 5):
        memory_ledger.record_event(
            consent_id=f"consent-{i:03d}",
            txnid=f"txn-{i:03d}",
            requested_purpose_code="101",
            requested_fi_type="DEPOSIT",
            decision="DENIED" if i == 2 else "AUTHORIZED",
            reason=f"REASON_{i}",
            agent_id=f"agent-{i}",
            output_sha256="NONE" if i == 2 else "abc",
        )

    # Initial verification passes
    is_valid, _ = memory_ledger.verify_chain_integrity()
    assert is_valid is True

    # Tamper with row 2 using raw SQL UPDATE (modifying decision from DENIED to AUTHORIZED)
    with memory_ledger._lock:
        with memory_ledger._conn:
            memory_ledger._conn.execute(
                "UPDATE dpdp_audit_ledger SET decision = 'AUTHORIZED' WHERE seq_id = 2"
            )

    # Verification must catch the tamper at seq_id 2
    is_valid, error_msg = memory_ledger.verify_chain_integrity()
    assert is_valid is False
    assert "Tamper detected" in error_msg
    assert "seq_id 2" in error_msg


def test_row_deletion_detection_via_sql_delete(memory_ledger: DPDPAuditLedger):
    """Test 3: Raw SQL DELETE on row 2 of a 4-row chain catches broken sequence/hash link."""
    # Append 4 valid events
    for i in range(1, 5):
        memory_ledger.record_event(
            consent_id=f"consent-{i:03d}",
            txnid=f"txn-{i:03d}",
            requested_purpose_code="101",
            requested_fi_type="DEPOSIT",
            decision="AUTHORIZED",
            reason=f"REASON_{i}",
            agent_id=f"agent-{i}",
            output_sha256="abc",
        )

    # Initial verification passes
    is_valid, _ = memory_ledger.verify_chain_integrity()
    assert is_valid is True

    # Tamper by deleting row 2
    with memory_ledger._lock:
        with memory_ledger._conn:
            memory_ledger._conn.execute(
                "DELETE FROM dpdp_audit_ledger WHERE seq_id = 2"
            )

    # Verification must catch the sequence or pointer break
    is_valid, error_msg = memory_ledger.verify_chain_integrity()
    assert is_valid is False
    assert "Tamper detected" in error_msg


def test_mcp_server_end_to_end_audit_and_zero_pii():
    """Test 4: End-to-end MCP tool execution with PII payload.

    Verifies query_consented_financial_context + verify_sovereign_audit_trail,
    confirming audit receipts and asserting zero PII enters the audit database.
    """
    # 1. Setup isolated in-memory audit ledger
    test_ledger = DPDPAuditLedger("sqlite:///:memory:")
    set_audit_ledger(test_ledger)

    # 2. Ephemeral RSA keypair and Fernet key
    priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    priv_pem = priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    pub_pem = priv_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    fernet_key = Fernet.generate_key().decode("utf-8")

    os.environ["AA_PUBLIC_KEY_PEM"] = pub_pem
    os.environ["FI_DECRYPTION_KEY"] = fernet_key

    # 3. Build consent artefact
    consent_id = f"consent-{uuid.uuid4()}"
    now = datetime.now(timezone.utc)
    jws_token = jwt.encode(
        {"consentId": consent_id, "sub": consent_id, "iat": int(now.timestamp())},
        priv_pem,
        algorithm="RS256",
    )
    artefact = RebitConsentArtefact(
        ver="2.0.0",
        txnid=str(uuid.uuid4()),
        consentId=consent_id,
        status=ConsentStatus.ACTIVE,
        createTimestamp=now,
        signedConsent=jws_token,
        consentDetail=ConsentDetail(
            consentStart=now,
            consentExpiry=now + datetime.resolution * 86400 * 30,
            consentMode=ConsentMode.VIEW,
            fetchType=FetchType.ONETIME,
            fiTypes=[FIType.DEPOSIT],
            purpose=PurposeDetail(
                code="101",
                text="Autonomous Credit Evaluation",
                refUri="https://api.rebit.org.in/purposes/101",
            ),
            dataConsumer=PartyIdentifier(id="AGENT_FIU", type="FIU"),
            dataProvider=PartyIdentifier(id="BANK_FIP", type="FIP"),
            customer=CustomerIdentifier(id="aarav@onemoney"),
        ),
    )

    # 4. Construct payload containing explicit customer PII
    pii_payload = {
        "Account": {
            "type": "SAVINGS",
            "currency": "INR",
            "Profile": {
                "Holders": {
                    "Holder": {
                        "name": "Aarav Sharma",
                        "pan": "ABCDE1234F",
                        "mobile": "9988776655",
                        "accountNumber": "9988776655443322",
                    }
                }
            },
            "Transactions": {
                "Transaction": [
                    {"type": "CREDIT", "amount": 80000.0, "narration": "TECH_SALARY_NOV"},
                    {"type": "DEBIT", "amount": 30000.0, "narration": "MORTGAGE_EMI"},
                ]
            },
        }
    }

    encrypted_blob = encrypt_fi_payload_fernet(pii_payload, fernet_key)

    # 5. Invoke MCP tool query_consented_financial_context
    response = query_consented_financial_context(
        consent_artefact_json=artefact.model_dump(),
        encrypted_fi_payload_b64=encrypted_blob,
        requested_purpose_code="101",
        requested_fi_type="DEPOSIT",
        agent_id="test-underwriter-agent",
    )

    assert response["status"] == "APPROVED"
    assert "audit_receipt" in response
    receipt = response["audit_receipt"]
    assert receipt["seq_id"] == 1
    assert len(receipt["entry_hash"]) == 64  # SHA-256 hex string

    # 6. Verify audit trail tool
    audit_status = verify_sovereign_audit_trail()
    assert audit_status["chain_valid"] is True
    assert audit_status["total_events"] == 1
    assert "DPDP_ACT_2023_TAMPER_EVIDENT" in audit_status["compliance"]

    # 7. CRITICAL SOVEREIGN AUDIT CHECK: Zero PII in audit database
    cur = test_ledger._conn.execute("SELECT * FROM dpdp_audit_ledger")
    rows = cur.fetchall()
    assert len(rows) == 1

    for row in rows:
        row_str = " ".join([str(val) for val in row])
        assert "Aarav Sharma" not in row_str
        assert "ABCDE1234F" not in row_str
        assert "9988776655" not in row_str
        assert "9988776655443322" not in row_str
        assert "Profile" not in row_str
        assert "Holders" not in row_str
