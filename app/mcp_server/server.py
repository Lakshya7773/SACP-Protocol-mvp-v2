"""Sovereign Agentic Context Protocol (SACP) Phase 4 FastMCP Server.

Exposes:
1. query_consented_financial_context: Gated context query with tamper-evident audit receipts.
2. verify_sovereign_audit_trail: Cryptographic audit chain health verification tool.

Hardened with Bearer Token API Gateway authentication on /mcp.
"""

import base64
import hashlib
import json
import logging
import os
import sys
import types
from typing import Any, Dict, Optional, Union

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp.server.mcpserver import MCPServer
from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.core.consent_gate import (
    ConsentExpiredError,
    ConsentNotYetValidError,
    ConsentRevokedError,
    ConsentViolationError,
    FITypeScopeViolationError,
    InvalidPurposeError,
    InvalidSignatureError,
    SovereignConsentGate,
    StoreConsentModeBlockedError,
)
from app.core.ephemeral_compute import (
    EphemeralComputeError,
    EphemeralRAMCompute,
    decrypt_rebit_ecdh_payload,
    generate_x25519_keypair,
)
from app.ledger.audit_ledger import DPDPAuditLedger
from app.models.rebit_schema import (
    FIType,
    RebitConsentArtefact,
)

logger = logging.getLogger("sacp.mcp_server")
logging.basicConfig(level=logging.INFO)

# ---------------------------------------------------------------------------
# Bearer Token API Gateway Authentication Middleware
# ---------------------------------------------------------------------------


class BearerAuthMiddleware(BaseHTTPMiddleware):
    """Enforces Bearer token authorization on all incoming HTTP requests."""

    def __init__(self, app: Any, api_key: Optional[str] = None) -> None:
        super().__init__(app)
        self.api_key = api_key

    async def dispatch(self, request: Any, call_next: Any) -> Any:
        # Exempt webhook routes and health checks from agent bearer token
        if request.url.path in ("/Consent/Notification", "/FI/Notification", "/health"):
            return await call_next(request)

        if self.api_key:
            auth_header = request.headers.get("authorization", "")
            expected_auth = f"Bearer {self.api_key}"
            if auth_header != expected_auth:
                return JSONResponse(
                    {
                        "error": "Unauthorized",
                        "detail": "Invalid or missing Bearer token in Authorization header.",
                    },
                    status_code=401,
                )
        return await call_next(request)


# ---------------------------------------------------------------------------
# FastMCP Implementation
# ---------------------------------------------------------------------------


class FastMCP(MCPServer):
    """FastMCP implementation over MCPServer supporting host/port configuration and auth middleware."""

    def __init__(
        self,
        name: str = "SACP",
        host: str = "0.0.0.0",
        port: int = 8000,
        **kwargs: Any,
    ) -> None:
        super().__init__(name=name, **kwargs)
        self.host = host
        self.port = port

    def streamable_http_app(self, *args: Any, **kwargs: Any) -> Starlette:
        """Create Starlette app with Bearer authentication and /mcp mount."""
        kwargs.setdefault("streamable_http_path", "/mcp")
        app = super().streamable_http_app(*args, **kwargs)

        # Mount ReBIT Webhook router
        try:
            from app.adapters.aa_sandbox_client import create_webhook_router

            webhook_router = create_webhook_router(consent_gate, audit_ledger)
            app.routes.extend(webhook_router.routes)
            logger.info("Mounted ReBIT AA Webhook endpoints: POST /Consent/Notification and POST /FI/Notification")
        except Exception as exc:
            logger.warning(f"Could not mount AA webhook router: {exc}")

        api_key = os.getenv("SACP_CLIENT_API_KEY")
        if api_key:
            app.add_middleware(BearerAuthMiddleware, api_key=api_key)
            logger.info("Bearer Token Authentication enabled on /mcp.")
        else:
            logger.warning(
                "[SECURITY WARNING] SACP_CLIENT_API_KEY is unset. Running in unauthenticated development mode."
            )

        return app

    def run(self, transport: str = "streamable-http", **kwargs: Any) -> None:
        """Run MCP Server on Streamable HTTP transport."""
        if transport == "streamable-http":
            host = kwargs.get("host", self.host)
            port = kwargs.get("port", self.port)
            app = self.streamable_http_app()
            import uvicorn

            uvicorn.run(app, host=host, port=port)
            return
        return super().run(transport=transport, **kwargs)


# Register module in sys.modules so `from mcp.server.fastmcp import FastMCP` resolves cleanly
if "mcp.server.fastmcp" not in sys.modules or not hasattr(sys.modules.get("mcp.server.fastmcp"), "FastMCP"):
    _fastmcp_mod = types.ModuleType("mcp.server.fastmcp")
    _fastmcp_mod.FastMCP = FastMCP
    sys.modules["mcp.server.fastmcp"] = _fastmcp_mod


# ---------------------------------------------------------------------------
# Key Management & Dev Fallback Generation
# ---------------------------------------------------------------------------


def generate_dev_keys() -> tuple[str, str, str]:
    """Generate ephemeral RSA-2048 and Fernet dev keys for local development and testing."""
    priv_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
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
    return priv_pem, pub_pem, fernet_key


DEV_RSA_PRIVATE_PEM, DEV_RSA_PUBLIC_PEM, DEV_FERNET_KEY = generate_dev_keys()
DEV_X25519_PRIVATE_PEM, DEV_X25519_PUBLIC_PEM = generate_x25519_keypair()


def get_aa_public_key() -> str:
    """Retrieve AA Public Key from environment or fallback to ephemeral dev key."""
    return os.getenv("AA_PUBLIC_KEY_PEM", DEV_RSA_PUBLIC_PEM)


def get_fi_decryption_key() -> str:
    """Retrieve FI Decryption Key from environment or fallback to ephemeral dev key."""
    return os.getenv("FI_DECRYPTION_KEY", DEV_FERNET_KEY)


def get_fiu_private_key() -> str:
    """Retrieve FIU X25519 Private Key from environment or fallback to ephemeral dev key."""
    return os.getenv("FIU_X25519_PRIVATE_KEY", DEV_X25519_PRIVATE_PEM)


# ---------------------------------------------------------------------------
# Shared Instances
# ---------------------------------------------------------------------------

consent_gate = SovereignConsentGate()
audit_ledger = DPDPAuditLedger()


def set_audit_ledger(ledger: DPDPAuditLedger) -> None:
    """Set active audit ledger (useful for isolated tests)."""
    global audit_ledger
    audit_ledger = ledger


# ---------------------------------------------------------------------------
# MCP Server & Tool Definitions
# ---------------------------------------------------------------------------

mcp = FastMCP(
    name="SovereignAgenticContextProtocol",
    host="0.0.0.0",
    port=8000,
    instructions=(
        "SACP Phase 4 MCP Server. Enforces zero-retention ReBIT v2.0+ Account Aggregator "
        "consent gating, in-memory ephemeral compute, and tamper-evident DPDP audit logging."
    ),
)


@mcp.tool()
def query_consented_financial_context(
    consent_artefact_json: Union[dict, str],
    encrypted_fi_payload_b64: str,
    requested_purpose_code: str,
    requested_fi_type: str = "DEPOSIT",
    is_revoked_live: bool = False,
    agent_id: str = "external-ai-agent",
    detached_jws: Optional[str] = None,
    fip_ephemeral_public_key_pem: Optional[str] = None,
    nonce_b64: Optional[str] = None,
    fiu_private_key_pem: Optional[str] = None,
    interop_headers: Optional[Dict[str, str]] = None,
) -> dict:
    """Query consented financial context with zero raw PII retention and tamper-evident audit receipts.

    Validates the ReBIT consent artefact, enforces sovereign policy (JWS signature,
    temporal validity, purpose code, FI type, live revocation, and blocking STORE mode),
    computes ephemeral cashflow metrics strictly in RAM, and logs a tamper-evident audit receipt.

    Args:
        consent_artefact_json: Dictionary or JSON string of RebitConsentArtefact.
        encrypted_fi_payload_b64: Base64 or string encrypted financial payload.
        requested_purpose_code: Purpose code matching consented purpose (e.g. '101').
        requested_fi_type: Requested FI type (defaults to 'DEPOSIT').
        is_revoked_live: Live revocation check boolean. If True, rejects immediately.
        agent_id: Identifier of the requesting AI agent.
        detached_jws: Optional detached JWS header string (header..signature) for ReBIT v2.0+.
        fip_ephemeral_public_key_pem: Optional FIP ephemeral X25519 public key (PEM) for forward-secrecy.
        nonce_b64: Optional base64-encoded 12-byte AES-GCM nonce for forward-secrecy.
        fiu_private_key_pem: Optional FIU private X25519 key (PEM). Falls back to env/dev key.
        interop_headers: Optional ReBIT interoperability headers dictionary.

    Returns:
        dict: Structured response with 'status' ('APPROVED' or 'DENIED_*'), data/error,
              and an 'audit_receipt' with seq_id and entry_hash.
    """
    # 1. Parse and validate consent artefact schema
    try:
        if isinstance(consent_artefact_json, str):
            parsed_json = json.loads(consent_artefact_json)
        else:
            parsed_json = consent_artefact_json
        artefact = RebitConsentArtefact.model_validate(parsed_json)
    except Exception as exc:
        receipt = audit_ledger.record_event(
            consent_id="UNKNOWN",
            txnid="UNKNOWN",
            agent_id=agent_id,
            requested_purpose_code=requested_purpose_code,
            requested_fi_type=requested_fi_type,
            decision="DENIED",
            reason="DENIED_INVALID_ARTEFACT",
            output_sha256="NONE",
        )
        return {
            "status": "DENIED_INVALID_ARTEFACT",
            "error": f"Schema validation failed: {exc}",
            "consent_id": None,
            "audit_receipt": {
                "seq_id": receipt["seq_id"],
                "entry_hash": receipt["entry_hash"],
            },
        }

    # 2. Enforce Sovereign Consent Gate policy
    try:
        raw_bytes = None
        if detached_jws:
            if isinstance(consent_artefact_json, str):
                raw_bytes = consent_artefact_json.encode("utf-8")
            else:
                raw_bytes = json.dumps(consent_artefact_json, separators=(",", ":")).encode("utf-8")

        consent_gate.enforce_policy(
            artefact=artefact,
            aa_public_key_pem=get_aa_public_key(),
            requested_purpose=requested_purpose_code,
            requested_fi_type=requested_fi_type,
            is_revoked_live=is_revoked_live,
            raw_payload_bytes=raw_bytes,
            detached_jws=detached_jws,
            interop_headers=interop_headers,
        )
    except InvalidSignatureError as exc:
        status_code = "DENIED_INVALID_SIGNATURE"
        receipt = audit_ledger.record_event(
            consent_id=artefact.consentId,
            txnid=artefact.txnid,
            agent_id=agent_id,
            requested_purpose_code=requested_purpose_code,
            requested_fi_type=requested_fi_type,
            decision="DENIED",
            reason=status_code,
            output_sha256="NONE",
        )
        return {
            "status": status_code,
            "error": str(exc),
            "consent_id": artefact.consentId,
            "audit_receipt": {
                "seq_id": receipt["seq_id"],
                "entry_hash": receipt["entry_hash"],
            },
        }
    except StoreConsentModeBlockedError as exc:
        status_code = "DENIED_STORE_MODE_BLOCKED"
        receipt = audit_ledger.record_event(
            consent_id=artefact.consentId,
            txnid=artefact.txnid,
            agent_id=agent_id,
            requested_purpose_code=requested_purpose_code,
            requested_fi_type=requested_fi_type,
            decision="DENIED",
            reason=status_code,
            output_sha256="NONE",
        )
        return {
            "status": status_code,
            "error": str(exc),
            "consent_id": artefact.consentId,
            "audit_receipt": {
                "seq_id": receipt["seq_id"],
                "entry_hash": receipt["entry_hash"],
            },
        }
    except ConsentRevokedError as exc:
        status_code = "DENIED_CONSENT_REVOKED"
        receipt = audit_ledger.record_event(
            consent_id=artefact.consentId,
            txnid=artefact.txnid,
            agent_id=agent_id,
            requested_purpose_code=requested_purpose_code,
            requested_fi_type=requested_fi_type,
            decision="DENIED",
            reason=status_code,
            output_sha256="NONE",
        )
        return {
            "status": status_code,
            "error": str(exc),
            "consent_id": artefact.consentId,
            "audit_receipt": {
                "seq_id": receipt["seq_id"],
                "entry_hash": receipt["entry_hash"],
            },
        }
    except ConsentExpiredError as exc:
        status_code = "DENIED_CONSENT_EXPIRED"
        receipt = audit_ledger.record_event(
            consent_id=artefact.consentId,
            txnid=artefact.txnid,
            agent_id=agent_id,
            requested_purpose_code=requested_purpose_code,
            requested_fi_type=requested_fi_type,
            decision="DENIED",
            reason=status_code,
            output_sha256="NONE",
        )
        return {
            "status": status_code,
            "error": str(exc),
            "consent_id": artefact.consentId,
            "audit_receipt": {
                "seq_id": receipt["seq_id"],
                "entry_hash": receipt["entry_hash"],
            },
        }
    except ConsentNotYetValidError as exc:
        status_code = "DENIED_CONSENT_NOT_YET_VALID"
        receipt = audit_ledger.record_event(
            consent_id=artefact.consentId,
            txnid=artefact.txnid,
            agent_id=agent_id,
            requested_purpose_code=requested_purpose_code,
            requested_fi_type=requested_fi_type,
            decision="DENIED",
            reason=status_code,
            output_sha256="NONE",
        )
        return {
            "status": status_code,
            "error": str(exc),
            "consent_id": artefact.consentId,
            "audit_receipt": {
                "seq_id": receipt["seq_id"],
                "entry_hash": receipt["entry_hash"],
            },
        }
    except InvalidPurposeError as exc:
        status_code = "DENIED_PURPOSE_MISMATCH"
        receipt = audit_ledger.record_event(
            consent_id=artefact.consentId,
            txnid=artefact.txnid,
            agent_id=agent_id,
            requested_purpose_code=requested_purpose_code,
            requested_fi_type=requested_fi_type,
            decision="DENIED",
            reason=status_code,
            output_sha256="NONE",
        )
        return {
            "status": status_code,
            "error": str(exc),
            "consent_id": artefact.consentId,
            "audit_receipt": {
                "seq_id": receipt["seq_id"],
                "entry_hash": receipt["entry_hash"],
            },
        }
    except FITypeScopeViolationError as exc:
        status_code = "DENIED_FI_TYPE_UNAUTHORIZED"
        receipt = audit_ledger.record_event(
            consent_id=artefact.consentId,
            txnid=artefact.txnid,
            agent_id=agent_id,
            requested_purpose_code=requested_purpose_code,
            requested_fi_type=requested_fi_type,
            decision="DENIED",
            reason=status_code,
            output_sha256="NONE",
        )
        return {
            "status": status_code,
            "error": str(exc),
            "consent_id": artefact.consentId,
            "audit_receipt": {
                "seq_id": receipt["seq_id"],
                "entry_hash": receipt["entry_hash"],
            },
        }
    except ConsentViolationError as exc:
        status_code = "DENIED_POLICY_VIOLATION"
        receipt = audit_ledger.record_event(
            consent_id=artefact.consentId,
            txnid=artefact.txnid,
            agent_id=agent_id,
            requested_purpose_code=requested_purpose_code,
            requested_fi_type=requested_fi_type,
            decision="DENIED",
            reason=status_code,
            output_sha256="NONE",
        )
        return {
            "status": status_code,
            "error": str(exc),
            "consent_id": artefact.consentId,
            "audit_receipt": {
                "seq_id": receipt["seq_id"],
                "entry_hash": receipt["entry_hash"],
            },
        }
    except Exception as exc:
        status_code = "DENIED_GATE_EXCEPTION"
        receipt = audit_ledger.record_event(
            consent_id=artefact.consentId,
            txnid=artefact.txnid,
            agent_id=agent_id,
            requested_purpose_code=requested_purpose_code,
            requested_fi_type=requested_fi_type,
            decision="DENIED",
            reason=status_code,
            output_sha256="NONE",
        )
        return {
            "status": status_code,
            "error": f"Unexpected gate evaluation error: {exc}",
            "consent_id": artefact.consentId,
            "audit_receipt": {
                "seq_id": receipt["seq_id"],
                "entry_hash": receipt["entry_hash"],
            },
        }

    # 3. Ephemeral In-RAM Decryption & Cashflow Computation
    try:
        compute_engine = EphemeralRAMCompute(get_fi_decryption_key())

        if fip_ephemeral_public_key_pem and nonce_b64:
            priv_key = fiu_private_key_pem or get_fiu_private_key() or DEV_X25519_PRIVATE_PEM
            ram_buffer = decrypt_rebit_ecdh_payload(
                encrypted_b64=encrypted_fi_payload_b64,
                fiu_private_x25519_pem=priv_key,
                fip_ephemeral_public_x25519_pem=fip_ephemeral_public_key_pem,
                nonce_b64=nonce_b64,
            )
            cashflow_summary = compute_engine.process_decrypted_buffer(
                ram_buffer=ram_buffer,
                consent_id=artefact.consentId,
                fi_type=requested_fi_type,
            )
        else:
            raw_encrypted = encrypted_fi_payload_b64.strip()
            try:
                decoded_bytes = base64.b64decode(raw_encrypted)
                if decoded_bytes.startswith(b"gAAAAA"):
                    payload_to_decrypt = decoded_bytes
                else:
                    payload_to_decrypt = raw_encrypted.encode("utf-8")
            except Exception:
                payload_to_decrypt = raw_encrypted.encode("utf-8")

            cashflow_summary = compute_engine.compute_cashflow_summary(
                encrypted_fi_blob=payload_to_decrypt,
                consent_id=artefact.consentId,
            )
    except EphemeralComputeError as exc:
        status_code = "DENIED_COMPUTE_ERROR"
        receipt = audit_ledger.record_event(
            consent_id=artefact.consentId,
            txnid=artefact.txnid,
            agent_id=agent_id,
            requested_purpose_code=requested_purpose_code,
            requested_fi_type=requested_fi_type,
            decision="DENIED",
            reason=status_code,
            output_sha256="NONE",
        )
        return {
            "status": status_code,
            "error": str(exc),
            "consent_id": artefact.consentId,
            "audit_receipt": {
                "seq_id": receipt["seq_id"],
                "entry_hash": receipt["entry_hash"],
            },
        }
    except Exception as exc:
        status_code = "DENIED_INTERNAL_ERROR"
        receipt = audit_ledger.record_event(
            consent_id=artefact.consentId,
            txnid=artefact.txnid,
            agent_id=agent_id,
            requested_purpose_code=requested_purpose_code,
            requested_fi_type=requested_fi_type,
            decision="DENIED",
            reason=status_code,
            output_sha256="NONE",
        )
        return {
            "status": status_code,
            "error": str(exc),
            "consent_id": artefact.consentId,
            "audit_receipt": {
                "seq_id": receipt["seq_id"],
                "entry_hash": receipt["entry_hash"],
            },
        }

    # 4. Approved zero-PII financial context + Audit Receipt
    canonical_output = json.dumps(cashflow_summary, sort_keys=True, separators=(",", ":"))
    output_digest = hashlib.sha256(canonical_output.encode("utf-8")).hexdigest()

    receipt = audit_ledger.record_event(
        consent_id=artefact.consentId,
        txnid=artefact.txnid,
        agent_id=agent_id,
        requested_purpose_code=requested_purpose_code,
        requested_fi_type=requested_fi_type,
        decision="AUTHORIZED",
        reason="CONSENT_VERIFIED_EPHEMERAL_COMPUTED",
        output_sha256=output_digest,
    )

    return {
        "status": "APPROVED",
        "consent_id": artefact.consentId,
        "data": cashflow_summary,
        "audit_receipt": {
            "seq_id": receipt["seq_id"],
            "entry_hash": receipt["entry_hash"],
        },
    }


@mcp.tool()
def verify_sovereign_audit_trail() -> dict:
    """Verifies cryptographic SHA-256 hash-chain integrity of the DPDP audit ledger.

    Recomputes hash pointers and content digests from genesis to head,
    confirming zero tampering, deletions, or row reordering.

    Returns:
        dict: Chain health status, total events count, and verification details.
    """
    is_valid, msg = audit_ledger.verify_chain_integrity()
    count = audit_ledger.count_entries()
    return {
        "chain_valid": is_valid,
        "total_events": count,
        "message": msg,
        "compliance": "DPDP_ACT_2023_TAMPER_EVIDENT",
    }


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
