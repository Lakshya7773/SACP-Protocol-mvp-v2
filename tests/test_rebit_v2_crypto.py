"""Comprehensive Test Suite for ReBIT v2.0+ Production Cryptography and AA Adapters (v0.2).

Tests:
1. ReBIT Detached JWS (x-jws-signature) generation, verification, and tamper rejection.
2. X25519 ECDH + HKDF-SHA256 + AES-256-GCM Forward-Secrecy in-RAM decryption across
   multi-FI types (DEPOSIT, GSTN, NPS) with zero-PII retention and buffer zero-wipe.
3. Live Citizen Revocation Webhook (POST /Consent/Notification) blocking subsequent agent queries.
4. AASandboxClient ReBIT v2.0+ request and mock flow.
"""

import asyncio
from datetime import datetime, timedelta, timezone
import json
import os
import uuid

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import pytest
from starlette.testclient import TestClient

from app.adapters.aa_sandbox_client import (
    AASandboxClient,
    create_webhook_router,
)
from app.core.consent_gate import (
    InvalidSignatureError,
    SovereignConsentGate,
    sign_detached_jws,
    verify_detached_jws,
)
from app.core.ephemeral_compute import (
    EphemeralRAMCompute,
    decrypt_rebit_ecdh_payload,
    encrypt_rebit_ecdh_payload,
    generate_x25519_keypair,
)
from app.ledger.audit_ledger import DPDPAuditLedger
from app.mcp_server import server
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


@pytest.fixture
def rsa_keypair():
    """Generate fresh RSA-2048 keypair for detached JWS tests."""
    priv = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return priv_pem, pub_pem


@pytest.fixture
def x25519_keypairs():
    """Generate FIU and FIP X25519 keypairs for forward-secrecy tests."""
    fiu_priv, fiu_pub = generate_x25519_keypair()
    fip_priv, fip_pub = generate_x25519_keypair()
    return {
        "fiu_priv": fiu_priv,
        "fiu_pub": fiu_pub,
        "fip_priv": fip_priv,
        "fip_pub": fip_pub,
    }


def _create_test_consent(consent_id: str, purpose_code: str = "101", fi_types=None):
    now = datetime.now(timezone.utc)
    detail = ConsentDetail(
        consentStart=now - timedelta(minutes=5),
        consentExpiry=now + timedelta(hours=2),
        consentMode=ConsentMode.VIEW,
        fetchType=FetchType.ONETIME,
        fiTypes=fi_types or [FIType.DEPOSIT, FIType.TERM_DEPOSIT],
        purpose=PurposeDetail(
            code=purpose_code,
            refUri="https://api.rebit.org.in/purpose/101.xml",
            text="Underwriting Analysis",
        ),
        dataConsumer=PartyIdentifier(id="FIU-SACP-PROD", type="FIU"),
        dataProvider=PartyIdentifier(id="FIP-BANK-PROD", type="FIP"),
        customer=CustomerIdentifier(id="citizen@sahamati"),
    )
    return RebitConsentArtefact(
        ver="2.0.0",
        txnid=str(uuid.uuid4()),
        consentId=consent_id,
        status=ConsentStatus.ACTIVE,
        createTimestamp=now,
        signedConsent="eyJhbGciOiJSUzI1NiJ9.dummy.sig",
        consentDetail=detail,
    )


# ---------------------------------------------------------------------------
# 1. ReBIT Detached JWS Tests
# ---------------------------------------------------------------------------


def test_detached_jws_sign_verify_and_tamper(rsa_keypair):
    """Verify ReBIT v2.0+ detached JWS signature generation and cryptographic tamper detection."""
    priv_pem, pub_pem = rsa_keypair
    payload = json.dumps({"consentId": "consent-rebit-100", "status": "ACTIVE"}).encode("utf-8")

    detached_sig = sign_detached_jws(payload, priv_pem)
    assert ".." in detached_sig, "Detached JWS must have header..signature format"

    # Valid verification
    assert verify_detached_jws(payload, detached_sig, pub_pem) is True

    # Tampered payload bytes must raise InvalidSignatureError
    tampered_payload = json.dumps({"consentId": "consent-rebit-100", "status": "TAMPERED"}).encode("utf-8")
    with pytest.raises(InvalidSignatureError):
        verify_detached_jws(tampered_payload, detached_sig, pub_pem)

    # Tampered signature bytes must fail
    header_part, sig_part = detached_sig.split("..")
    tampered_sig = f"{header_part}..{sig_part[:-4]}AAAA"
    with pytest.raises(InvalidSignatureError):
        verify_detached_jws(payload, tampered_sig, pub_pem)


# ---------------------------------------------------------------------------
# 2. ReBIT Forward-Secrecy Multi-FI Ephemeral In-RAM Decryption Tests
# ---------------------------------------------------------------------------


def test_forward_secrecy_deposit_zero_pii_and_ram_zero_wipe(x25519_keypairs):
    """Test X25519 ECDH + AES-256-GCM forward-secrecy on DEPOSIT payload with PII stripping & zero-wipe."""
    keys = x25519_keypairs
    deposit_payload = {
        "Account": {
            "type": "deposit",
            "currency": "INR",
            "maskedAccNumber": "XXXXXXXX9876",
            "Profile": {
                "Holders": {
                    "Holder": {
                        "name": "Aditya Sharma",
                        "pan": "ABCDE1234F",
                        "mobile": "+919999988888",
                        "email": "aditya@domain.com",
                    }
                }
            },
            "Transactions": {
                "Transaction": [
                    {"txnId": "tx-1", "type": "CREDIT", "amount": 100000.0, "narration": "Salary Nov"},
                    {"txnId": "tx-2", "type": "DEBIT", "amount": 35000.0, "narration": "Rent"},
                    {"txnId": "tx-3", "type": "DEBIT", "amount": 15000.0, "narration": "Groceries"},
                ]
            },
        }
    }

    # FIP encrypts using FIP Ephemeral Private + FIU Public Key
    enc_res = encrypt_rebit_ecdh_payload(
        payload=deposit_payload,
        fip_ephemeral_private_pem=keys["fip_priv"],
        fiu_public_pem=keys["fiu_pub"],
    )
    enc_b64 = enc_res["encrypted_b64"]
    nonce_b64 = enc_res["nonce_b64"]

    # FIU decrypts in RAM using FIU Private + FIP Ephemeral Public Key
    ram_buffer = decrypt_rebit_ecdh_payload(
        encrypted_b64=enc_b64,
        fiu_private_x25519_pem=keys["fiu_priv"],
        fip_ephemeral_public_x25519_pem=keys["fip_pub"],
        nonce_b64=nonce_b64,
    )
    assert isinstance(ram_buffer, bytearray)

    compute = EphemeralRAMCompute()
    # Process buffer and compute summary
    summary = compute.process_decrypted_buffer(ram_buffer, consent_id="consent-dep-001", fi_type="DEPOSIT")

    # Exact math checks
    assert summary["total_inflow"] == 100000.0
    assert summary["total_outflow"] == 50000.0
    assert summary["net_surplus"] == 50000.0
    assert summary["credit_transactions"] == 1
    assert summary["debit_transactions"] == 2

    # Zero PII retention checks
    summary_str = json.dumps(summary)
    assert "Aditya Sharma" not in summary_str
    assert "ABCDE1234F" not in summary_str
    assert "XXXXXXXX9876" not in summary_str
    assert "aditya@domain.com" not in summary_str
    assert "+919999988888" not in summary_str

    # Buffer zero-wipe verification (RAM buffer must be cleared to 0)
    assert len(ram_buffer) == 0 or all(b == 0 for b in ram_buffer)


def test_forward_secrecy_gstn_turnover_processing(x25519_keypairs):
    """Test X25519 ECDH forward secrecy on GSTN invoices with PII stripping."""
    keys = x25519_keypairs
    gstn_payload = {
        "Account": {
            "type": "gstn",
            "currency": "INR",
            "Profile": {
                "gstin": "27AAPFU0939F1ZV",
                "pan": "AAPFU0939F",
                "legalName": "Apex Technologies Pvt Ltd",
                "tradeName": "Apex Tech",
            },
            "Invoices": [
                {"invoiceNumber": "INV-001", "invoiceValue": 550000.0, "taxableValue": 500000.0, "gstin": "27AAPFU0939F1ZV"},
                {"invoiceNumber": "INV-002", "invoiceValue": 275000.0, "taxableValue": 250000.0, "gstin": "27AAPFU0939F1ZV"},
            ],
        }
    }

    enc_res = encrypt_rebit_ecdh_payload(
        payload=gstn_payload,
        fip_ephemeral_private_pem=keys["fip_priv"],
        fiu_public_pem=keys["fiu_pub"],
    )
    enc_b64 = enc_res["encrypted_b64"]
    nonce_b64 = enc_res["nonce_b64"]

    ram_buffer = decrypt_rebit_ecdh_payload(
        encrypted_b64=enc_b64,
        fiu_private_x25519_pem=keys["fiu_priv"],
        fip_ephemeral_public_x25519_pem=keys["fip_pub"],
        nonce_b64=nonce_b64,
    )

    compute = EphemeralRAMCompute()
    summary = compute.process_decrypted_buffer(ram_buffer, consent_id="consent-gst-002", fi_type="GSTN")

    assert summary["fi_type"] == "GSTN"
    assert summary["total_turnover"] == 825000.0
    assert summary["total_taxable_value"] == 750000.0
    assert summary["total_invoices"] == 2

    # Zero PII assertions
    out_json = json.dumps(summary)
    assert "27AAPFU0939F1ZV" not in out_json
    assert "AAPFU0939F" not in out_json
    assert "Apex Technologies" not in out_json


def test_forward_secrecy_nps_pension_contributions(x25519_keypairs):
    """Test X25519 ECDH forward secrecy on NPS pension contributions."""
    keys = x25519_keypairs
    nps_payload = {
        "Account": {
            "type": "nps",
            "currency": "INR",
            "Profile": {
                "pran": "110022334455",
                "subscriberName": "Pooja Verma",
                "pan": "PQRST5678G",
            },
            "Contributions": [
                {"tier": "TIER_1", "amount": 50000.0, "date": "2026-03-15"},
                {"tier": "TIER_1", "amount": 50000.0, "date": "2026-06-15"},
                {"tier": "TIER_2", "amount": 25000.0, "date": "2026-09-15"},
            ],
        }
    }

    enc_res = encrypt_rebit_ecdh_payload(
        payload=nps_payload,
        fip_ephemeral_private_pem=keys["fip_priv"],
        fiu_public_pem=keys["fiu_pub"],
    )
    enc_b64 = enc_res["encrypted_b64"]
    nonce_b64 = enc_res["nonce_b64"]

    ram_buffer = decrypt_rebit_ecdh_payload(
        encrypted_b64=enc_b64,
        fiu_private_x25519_pem=keys["fiu_priv"],
        fip_ephemeral_public_x25519_pem=keys["fip_pub"],
        nonce_b64=nonce_b64,
    )

    compute = EphemeralRAMCompute()
    summary = compute.process_decrypted_buffer(ram_buffer, consent_id="consent-nps-003", fi_type="NPS")

    assert summary["fi_type"] == "NPS"
    assert summary["tier1_contributions"] == 100000.0
    assert summary["tier2_contributions"] == 25000.0
    assert summary["total_nps_contributions"] == 125000.0

    # Zero PII assertions
    out_json = json.dumps(summary)
    assert "110022334455" not in out_json
    assert "Pooja Verma" not in out_json
    assert "PQRST5678G" not in out_json


# ---------------------------------------------------------------------------
# 3. Live Citizen Revocation Webhook & Gateway Block Test
# ---------------------------------------------------------------------------


def test_live_citizen_revocation_webhook_blocks_mcp(x25519_keypairs, rsa_keypair):
    """Test citizen revoking consent on AA app via webhook instantly blocks subsequent queries."""
    priv_rsa, pub_rsa = rsa_keypair
    keys = x25519_keypairs
    consent_id = f"consent-{uuid.uuid4()}"

    # Setup isolated test ledger & gate
    test_db = f":memory:"
    ledger = DPDPAuditLedger(db_url=f"sqlite:///{test_db}")
    set_audit_ledger(ledger)

    gate = SovereignConsentGate()
    server.consent_gate = gate
    os.environ["AA_PUBLIC_KEY_PEM"] = pub_rsa

    artefact = _create_test_consent(consent_id, purpose_code="101")
    # Sign artefact with detached JWS
    artefact_dict = artefact.model_dump(mode="json", by_alias=True)
    raw_payload_bytes = json.dumps(artefact_dict, separators=(",", ":")).encode("utf-8")
    detached_sig = sign_detached_jws(raw_payload_bytes, priv_rsa)

    # Prepare encrypted mock payload
    deposit_payload = {
        "Account": {
            "type": "deposit",
            "currency": "INR",
            "Transactions": {
                "Transaction": [{"type": "CREDIT", "amount": 10000.0}]
            },
        }
    }
    enc_res = encrypt_rebit_ecdh_payload(
        payload=deposit_payload,
        fip_ephemeral_private_pem=keys["fip_priv"],
        fiu_public_pem=keys["fiu_pub"],
    )
    enc_b64 = enc_res["encrypted_b64"]
    nonce_b64 = enc_res["nonce_b64"]

    # 1. Initial Call: Should be APPROVED
    res1 = query_consented_financial_context(
        consent_artefact_json=artefact_dict,
        encrypted_fi_payload_b64=enc_b64,
        requested_purpose_code="101",
        requested_fi_type="DEPOSIT",
        is_revoked_live=False,
        agent_id="test-underwriter",
        detached_jws=detached_sig,
        fip_ephemeral_public_key_pem=keys["fip_pub"],
        nonce_b64=nonce_b64,
        fiu_private_key_pem=keys["fiu_priv"],
    )
    assert res1["status"] == "APPROVED"
    assert res1["data"]["total_inflow"] == 10000.0

    # 2. Citizen revokes consent on AA app -> Webhook POST /Consent/Notification
    router = create_webhook_router(gate, ledger)
    from starlette.applications import Starlette
    webhook_app = Starlette(routes=router.routes)
    client = TestClient(webhook_app)

    revoke_payload = {
        "ver": "2.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "txnid": str(uuid.uuid4()),
        "ConsentStatusNotification": {
            "consentId": consent_id,
            "consentHandle": "handle-xyz",
            "consentStatus": "REVOKED",
        },
    }
    webhook_resp = client.post("/Consent/Notification", json=revoke_payload)
    assert webhook_resp.status_code == 200
    assert webhook_resp.json()["status"] == "OK"

    # Verify gate registered revocation
    assert gate.is_consent_revoked(consent_id) is True

    # 3. Subsequent Agent Query with identical payload: Must immediately FAIL CLOSED
    res2 = query_consented_financial_context(
        consent_artefact_json=artefact_dict,
        encrypted_fi_payload_b64=enc_b64,
        requested_purpose_code="101",
        requested_fi_type="DEPOSIT",
        is_revoked_live=False,
        agent_id="test-underwriter",
        detached_jws=detached_sig,
        fip_ephemeral_public_key_pem=keys["fip_pub"],
        nonce_b64=nonce_b64,
        fiu_private_key_pem=keys["fiu_priv"],
    )
    assert res2["status"] == "DENIED_CONSENT_REVOKED"
    assert res2["audit_receipt"]["seq_id"] >= 2


# ---------------------------------------------------------------------------
# 4. AASandboxClient Flow Test
# ---------------------------------------------------------------------------


def test_aa_sandbox_client_mock_flow():
    """Verify AASandboxClient operations in simulated sandbox mode."""
    async def _run():
        client = AASandboxClient(mock_mode=True)
        consent = _create_test_consent("consent-mock-123")
        res_consent = await client.create_consent_request(consent.consentDetail)
        assert res_consent["status"] == "PENDING"
        assert "ConsentHandle" in res_consent

        handle = res_consent["ConsentHandle"]
        res_status = await client.get_consent_status(handle)
        assert res_status["ConsentStatus"]["status"] == "ACTIVE"

        res_fi_req = await client.request_fi_data(
            consent_id="consent-mock-123",
            fiu_x25519_pub_pem="dummy-pub",
            date_range={"from": "2026-01-01", "to": "2026-03-01"},
        )
        assert "sessionId" in res_fi_req

        session_id = res_fi_req["sessionId"]
        res_fi = await client.fetch_fi_data(session_id)
        assert "FI" in res_fi

    asyncio.run(_run())
