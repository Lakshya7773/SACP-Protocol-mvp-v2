"""Comprehensive Pytest Test Suite for Sovereign Agentic Context Protocol (SACP) Phase 2.

Covers the 6 core sovereign security & zero-retention requirements:
a) Valid RS256 JWS consent + Fernet encrypted mock FI payload with PII (Profile
   containing name, PAN, accountNumber) verifying exact cashflow math and asserting
   zero PII appears in the serialized output.
b) Tampered JWS signature rejection (ConsentViolationError).
c) Live revocation (is_revoked_live=True) immediate rejection.
d) Purpose code mismatch rejection.
e) Expired consent window rejection.
f) ConsentMode.STORE blocked for external agents.
"""

import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, Tuple

import jwt
import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.core.consent_gate import (
    ConsentExpiredError,
    ConsentRevokedError,
    ConsentViolationError,
    InvalidPurposeError,
    InvalidSignatureError,
    SovereignConsentGate,
    StoreConsentModeBlockedError,
)
from app.core.ephemeral_compute import (
    EphemeralRAMCompute,
    encrypt_fi_payload_fernet,
)
from app.ledger.audit_ledger import DPDPAuditLedger
from app.mcp_server.server import (
    query_consented_financial_context,
    set_audit_ledger,
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


@pytest.fixture(scope="session")
def rsa_keypair() -> Tuple[str, str]:
    """Generate ephemeral RSA-2048 keypair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    return private_pem, public_pem


@pytest.fixture(scope="session")
def fernet_key() -> str:
    """Generate ephemeral Fernet key."""
    return Fernet.generate_key().decode("utf-8")


@pytest.fixture(autouse=True)
def configure_dev_env(rsa_keypair, fernet_key):
    """Ensure environment variables match session test keys and ledger is fresh."""
    _, public_pem = rsa_keypair
    os.environ["AA_PUBLIC_KEY_PEM"] = public_pem
    os.environ["FI_DECRYPTION_KEY"] = fernet_key
    ledger = DPDPAuditLedger("sqlite:///:memory:")
    set_audit_ledger(ledger)
    yield
    set_audit_ledger(DPDPAuditLedger("sqlite:///:memory:"))


@pytest.fixture
def mock_fi_payload_with_pii() -> Dict:
    """Mock Account Aggregator FI payload containing sensitive customer PII in Profile."""
    return {
        "Account": {
            "type": "SAVINGS",
            "currency": "INR",
            "Profile": {
                "Holders": {
                    "Holder": {
                        "name": "Aditi Sharma",
                        "pan": "ABCDE1234F",
                        "mobile": "9876543210",
                        "email": "aditi.sharma@example.com",
                        "accountNumber": "9876543210123456",
                    }
                }
            },
            "Transactions": {
                "Transaction": [
                    {
                        "txnId": "TXN_001",
                        "type": "CREDIT",
                        "amount": 75000.0,
                        "narration": "MONTHLY SALARY CREDIT",
                    },
                    {
                        "txnId": "TXN_002",
                        "type": "DEBIT",
                        "amount": 25000.0,
                        "narration": "APARTMENT RENT TRANSFER",
                    },
                    {
                        "txnId": "TXN_003",
                        "type": "CREDIT",
                        "amount": 45000.0,
                        "narration": "FREELANCE CONTRACT SETTLEMENT",
                    },
                    {
                        "txnId": "TXN_004",
                        "type": "DEBIT",
                        "amount": 15000.0,
                        "narration": "GROCERY AND UTILITIES",
                    },
                ]
            },
        }
    }


def sign_jws_token(consent_id: str, private_key_pem: str) -> str:
    """Sign RS256 JWS token for consent artefact."""
    claims = {
        "consentId": consent_id,
        "sub": consent_id,
        "iss": "https://aa.onemoney.in",
        "iat": int(datetime.now(timezone.utc).timestamp()),
    }
    return jwt.encode(claims, private_key_pem, algorithm="RS256")


def build_artefact(
    consent_id: str,
    private_key_pem: str,
    consent_mode: ConsentMode = ConsentMode.VIEW,
    status: ConsentStatus = ConsentStatus.ACTIVE,
    purpose_code: str = "101",
    fi_types=None,
    start_offset_days: int = -2,
    expiry_offset_days: int = 30,
) -> RebitConsentArtefact:
    """Helper to build test RebitConsentArtefact instances."""
    if fi_types is None:
        fi_types = [FIType.DEPOSIT]

    now = datetime.now(timezone.utc)
    signed_jws = sign_jws_token(consent_id, private_key_pem)

    detail = ConsentDetail(
        consentStart=now + timedelta(days=start_offset_days),
        consentExpiry=now + timedelta(days=expiry_offset_days),
        consentMode=consent_mode,
        fetchType=FetchType.ONETIME,
        fiTypes=fi_types,
        purpose=PurposeDetail(
            code=purpose_code,
            text="Autonomous Credit & Cashflow Underwriting",
            refUri="https://api.rebit.org.in/purposes/101",
        ),
        dataConsumer=PartyIdentifier(id="AGENT_UNDERWRITER_FIU", type="FIU"),
        dataProvider=PartyIdentifier(id="AXIS_BANK_FIP", type="FIP"),
        customer=CustomerIdentifier(id="aditi@onemoney"),
    )

    return RebitConsentArtefact(
        ver="2.0.0",
        txnid=str(uuid.uuid4()),
        consentId=consent_id,
        status=status,
        createTimestamp=now,
        signedConsent=signed_jws,
        consentDetail=detail,
    )


# ============================================================================
# Test Cases (a through f)
# ============================================================================


def test_a_valid_consent_pii_stripped_and_exact_math(
    rsa_keypair, fernet_key, mock_fi_payload_with_pii
):
    """Test (a): Valid RS256 JWS consent + Fernet encrypted payload with PII.

    Verifies exact cashflow math and asserts zero PII appears in serialized output.
    """
    private_pem, public_pem = rsa_keypair
    consent_id = f"consent-{uuid.uuid4()}"

    artefact = build_artefact(
        consent_id=consent_id,
        private_key_pem=private_pem,
        consent_mode=ConsentMode.VIEW,
        purpose_code="101",
        fi_types=[FIType.DEPOSIT],
    )

    encrypted_payload_token = encrypt_fi_payload_fernet(
        mock_fi_payload_with_pii,
        fernet_key=fernet_key,
    )

    # 1. Direct Gate enforcement passes
    gate = SovereignConsentGate()
    assert gate.enforce_policy(
        artefact=artefact,
        aa_public_key_pem=public_pem,
        requested_purpose="101",
        requested_fi_type=FIType.DEPOSIT,
        is_revoked_live=False,
    )

    # 2. Ephemeral In-RAM Compute & PII Stripping
    compute = EphemeralRAMCompute(fernet_key)
    summary = compute.compute_cashflow_summary(
        encrypted_fi_blob=encrypted_payload_token,
        consent_id=consent_id,
    )

    # Verify exact cashflow arithmetic:
    # Inflows: 75,000 + 45,000 = 120,000.0
    # Outflows: 25,000 + 15,000 = 40,000.0
    # Net surplus: 80,000.0
    assert summary["total_inflow"] == 120000.0
    assert summary["total_outflow"] == 40000.0
    assert summary["net_surplus"] == 80000.0
    assert summary["credit_transactions"] == 2
    assert summary["debit_transactions"] == 2
    assert summary["consent_id"] == consent_id

    # 3. FastMCP tool invocation test
    response = query_consented_financial_context(
        consent_artefact_json=artefact.model_dump(),
        encrypted_fi_payload_b64=encrypted_payload_token,
        requested_purpose_code="101",
        requested_fi_type="DEPOSIT",
        is_revoked_live=False,
    )

    assert response["status"] == "APPROVED"
    assert response["consent_id"] == consent_id
    assert response["data"]["total_inflow"] == 120000.0
    assert response["data"]["total_outflow"] == 40000.0
    assert response["data"]["net_surplus"] == 80000.0

    # 4. Critical Sovereign Assertion: ZERO PII in output
    serialized_output = json.dumps(response)
    assert "Aditi Sharma" not in serialized_output
    assert "ABCDE1234F" not in serialized_output
    assert "9876543210" not in serialized_output
    assert "9876543210123456" not in serialized_output
    assert "aditi.sharma@example.com" not in serialized_output
    assert "Profile" not in serialized_output
    assert "Holders" not in serialized_output


def test_b_tampered_jws_signature_rejection(rsa_keypair, fernet_key, mock_fi_payload_with_pii):
    """Test (b): Tampered JWS signature rejection (ConsentViolationError)."""
    private_pem, public_pem = rsa_keypair
    consent_id = f"consent-{uuid.uuid4()}"

    valid_artefact = build_artefact(consent_id=consent_id, private_key_pem=private_pem)
    # Tamper with the cryptographic signature characters
    tampered_jws = valid_artefact.signedConsent[:-8] + "TAMPERED"
    tampered_artefact = valid_artefact.model_copy(update={"signedConsent": tampered_jws})

    gate = SovereignConsentGate()
    # Direct gate enforcement must raise ConsentViolationError
    with pytest.raises(ConsentViolationError) as exc_info:
        gate.enforce_policy(
            artefact=tampered_artefact,
            aa_public_key_pem=public_pem,
            requested_purpose="101",
            requested_fi_type="DEPOSIT",
        )
    assert issubclass(exc_info.type, ConsentViolationError)

    # Tool invocation fails closed with DENIED_INVALID_SIGNATURE
    encrypted_token = encrypt_fi_payload_fernet(mock_fi_payload_with_pii, fernet_key)
    response = query_consented_financial_context(
        consent_artefact_json=tampered_artefact.model_dump(),
        encrypted_fi_payload_b64=encrypted_token,
        requested_purpose_code="101",
        requested_fi_type="DEPOSIT",
    )
    assert response["status"] == "DENIED_INVALID_SIGNATURE"
    assert "failed" in response["error"].lower()


def test_c_live_revocation_rejection(rsa_keypair, fernet_key, mock_fi_payload_with_pii):
    """Test (c): Live revocation (is_revoked_live=True) immediate rejection."""
    private_pem, public_pem = rsa_keypair
    consent_id = f"consent-{uuid.uuid4()}"

    artefact = build_artefact(
        consent_id=consent_id,
        private_key_pem=private_pem,
        status=ConsentStatus.ACTIVE,
    )

    gate = SovereignConsentGate()
    # Direct gate raises ConsentViolationError when is_revoked_live=True
    with pytest.raises(ConsentViolationError) as exc_info:
        gate.enforce_policy(
            artefact=artefact,
            aa_public_key_pem=public_pem,
            requested_purpose="101",
            requested_fi_type="DEPOSIT",
            is_revoked_live=True,  # Live revoked!
        )
    assert issubclass(exc_info.type, ConsentRevokedError)
    assert issubclass(exc_info.type, ConsentViolationError)

    # Tool fails closed with DENIED_CONSENT_REVOKED
    encrypted_token = encrypt_fi_payload_fernet(mock_fi_payload_with_pii, fernet_key)
    response = query_consented_financial_context(
        consent_artefact_json=artefact.model_dump(),
        encrypted_fi_payload_b64=encrypted_token,
        requested_purpose_code="101",
        requested_fi_type="DEPOSIT",
        is_revoked_live=True,
    )
    assert response["status"] == "DENIED_CONSENT_REVOKED"
    assert "live revocation check" in response["error"]


def test_d_purpose_code_mismatch_rejection(rsa_keypair, fernet_key, mock_fi_payload_with_pii):
    """Test (d): Purpose code mismatch rejection."""
    private_pem, public_pem = rsa_keypair
    consent_id = f"consent-{uuid.uuid4()}"

    artefact = build_artefact(
        consent_id=consent_id,
        private_key_pem=private_pem,
        purpose_code="101",  # Consented for 101
    )

    gate = SovereignConsentGate()
    # Requesting with 102 must raise ConsentViolationError / InvalidPurposeError
    with pytest.raises(ConsentViolationError) as exc_info:
        gate.enforce_policy(
            artefact=artefact,
            aa_public_key_pem=public_pem,
            requested_purpose="102",  # Mismatch!
            requested_fi_type="DEPOSIT",
        )
    assert issubclass(exc_info.type, InvalidPurposeError)
    assert issubclass(exc_info.type, ConsentViolationError)

    # Tool fails closed with DENIED_PURPOSE_MISMATCH
    encrypted_token = encrypt_fi_payload_fernet(mock_fi_payload_with_pii, fernet_key)
    response = query_consented_financial_context(
        consent_artefact_json=artefact.model_dump(),
        encrypted_fi_payload_b64=encrypted_token,
        requested_purpose_code="102",  # Mismatched purpose code
        requested_fi_type="DEPOSIT",
    )
    assert response["status"] == "DENIED_PURPOSE_MISMATCH"
    assert "102" in response["error"]


def test_e_expired_consent_window_rejection(rsa_keypair, fernet_key, mock_fi_payload_with_pii):
    """Test (e): Expired consent window rejection."""
    private_pem, public_pem = rsa_keypair
    consent_id = f"consent-{uuid.uuid4()}"

    # Consent expired yesterday
    expired_artefact = build_artefact(
        consent_id=consent_id,
        private_key_pem=private_pem,
        start_offset_days=-30,
        expiry_offset_days=-1,
    )

    gate = SovereignConsentGate()
    # Direct gate raises ConsentViolationError / ConsentExpiredError
    with pytest.raises(ConsentViolationError) as exc_info:
        gate.enforce_policy(
            artefact=expired_artefact,
            aa_public_key_pem=public_pem,
            requested_purpose="101",
            requested_fi_type="DEPOSIT",
        )
    assert issubclass(exc_info.type, ConsentExpiredError)
    assert issubclass(exc_info.type, ConsentViolationError)

    # Tool fails closed with DENIED_CONSENT_EXPIRED
    encrypted_token = encrypt_fi_payload_fernet(mock_fi_payload_with_pii, fernet_key)
    response = query_consented_financial_context(
        consent_artefact_json=expired_artefact.model_dump(),
        encrypted_fi_payload_b64=encrypted_token,
        requested_purpose_code="101",
        requested_fi_type="DEPOSIT",
    )
    assert response["status"] == "DENIED_CONSENT_EXPIRED"
    assert "expired" in response["error"].lower()


def test_f_store_mode_blocked_rejection(rsa_keypair, fernet_key, mock_fi_payload_with_pii):
    """Test (f): ConsentMode.STORE blocked for external agents."""
    private_pem, public_pem = rsa_keypair
    consent_id = f"consent-{uuid.uuid4()}"

    store_artefact = build_artefact(
        consent_id=consent_id,
        private_key_pem=private_pem,
        consent_mode=ConsentMode.STORE,  # Strictly prohibited
    )

    gate = SovereignConsentGate()
    # Direct gate raises ConsentViolationError / StoreConsentModeBlockedError
    with pytest.raises(ConsentViolationError) as exc_info:
        gate.enforce_policy(
            artefact=store_artefact,
            aa_public_key_pem=public_pem,
            requested_purpose="101",
            requested_fi_type="DEPOSIT",
        )
    assert issubclass(exc_info.type, StoreConsentModeBlockedError)
    assert issubclass(exc_info.type, ConsentViolationError)

    # Tool fails closed with DENIED_STORE_MODE_BLOCKED
    encrypted_token = encrypt_fi_payload_fernet(mock_fi_payload_with_pii, fernet_key)
    response = query_consented_financial_context(
        consent_artefact_json=store_artefact.model_dump(),
        encrypted_fi_payload_b64=encrypted_token,
        requested_purpose_code="101",
        requested_fi_type="DEPOSIT",
    )
    assert response["status"] == "DENIED_STORE_MODE_BLOCKED"
    assert "strictly prohibited" in response["error"].lower()
