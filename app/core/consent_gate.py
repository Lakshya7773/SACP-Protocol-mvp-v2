"""Sovereign Consent Gate Implementation (v0.2).

Enforces zero-trust cryptographic and policy validation on ReBIT v2.0+
consent artefacts before allowing ephemeral compute or agentic data access.
Supports both embedded RS256 JWS and ReBIT native Detached JWS (x-jws-signature).
"""

import base64
from datetime import datetime, timezone
import json
import threading
from typing import Any, Callable, Dict, Optional, Set, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import jwt

from app.models.rebit_schema import (
    ConsentMode,
    ConsentStatus,
    FIType,
    RebitConsentArtefact,
)


class SACPError(Exception):
    """Base exception for all SACP protocol errors."""


class ConsentViolationError(SACPError):
    """Base exception for all consent and gate policy violations."""


class ConsentGateError(ConsentViolationError):
    """Alias/subclass for consent gate validation failures."""


class InvalidSignatureError(ConsentViolationError):
    """Raised when JWS cryptographic signature is invalid or tampered."""


class StoreConsentModeBlockedError(ConsentViolationError):
    """Raised when consent specifies STORE mode, which violates sovereign zero-retention."""


class ConsentTemporalWindowError(ConsentViolationError):
    """Base exception for temporal window boundary violations."""


class ConsentExpiredError(ConsentTemporalWindowError):
    """Raised when consent expiry timestamp is in the past."""


class ConsentNotYetValidError(ConsentTemporalWindowError):
    """Raised when consent start timestamp is in the future."""


class InvalidPurposeError(ConsentViolationError):
    """Raised when requested purpose does not match consented purpose code."""


class FITypeScopeViolationError(ConsentViolationError):
    """Raised when requested FI type is not within consented fiTypes."""


class ConsentRevokedError(ConsentViolationError):
    """Raised when consent has been revoked by customer, AA, or live check."""


class RebitInteropHeaderError(ConsentViolationError):
    """Raised when required ReBIT interoperability headers are invalid."""


def _base64url_decode(input_str: str) -> bytes:
    """Helper to decode base64url string with proper padding."""
    rem = len(input_str) % 4
    if rem > 0:
        input_str += "=" * (4 - rem)
    return base64.urlsafe_b64decode(input_str)


def _base64url_encode(input_bytes: bytes) -> str:
    """Helper to encode bytes to unpadded base64url string."""
    return base64.urlsafe_b64encode(input_bytes).decode("ascii").rstrip("=")


def sign_detached_jws(
    raw_payload_bytes: bytes,
    private_key_pem: Union[str, bytes],
    extra_headers: Optional[Dict[str, Any]] = None,
) -> str:
    """Produce a ReBIT v2.0+ detached JWS signature (header..signature).

    Args:
        raw_payload_bytes: Exact bytes of the JSON payload.
        private_key_pem: RSA private key in PEM format.
        extra_headers: Optional extra JWS header claims.

    Returns:
        str: Detached JWS string in 'base64url(header)..base64url(signature)' format.
    """
    if isinstance(private_key_pem, str):
        key_bytes = private_key_pem.encode("utf-8")
    else:
        key_bytes = private_key_pem

    priv_key = serialization.load_pem_private_key(key_bytes, password=None, backend=default_backend())

    header_dict = {"alg": "RS256", "typ": "JWT"}
    if extra_headers:
        header_dict.update(extra_headers)

    header_b64 = _base64url_encode(json.dumps(header_dict, separators=(",", ":")).encode("utf-8"))
    signing_input = header_b64.encode("ascii") + b"." + raw_payload_bytes

    signature = priv_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    signature_b64 = _base64url_encode(signature)

    return f"{header_b64}..{signature_b64}"


def verify_detached_jws(
    raw_payload_bytes: bytes,
    detached_jws_header: str,
    aa_public_key_pem: Union[str, bytes],
) -> bool:
    """Verify a ReBIT standard detached JWS signature (x-jws-signature).

    In ReBIT v2.0+, HTTP payloads are accompanied by detached JWS format:
    'base64url(header)..base64url(signature)' where the signature is computed
    over ASCII(header_b64) + '.' + raw_payload_bytes.

    Args:
        raw_payload_bytes: The exact raw bytes of the HTTP body / JSON payload.
        detached_jws_header: Detached JWS signature string from x-jws-signature.
        aa_public_key_pem: RSA public key in PEM format.

    Returns:
        bool: True if signature is cryptographically valid.

    Raises:
        InvalidSignatureError: If signature is invalid, malformed, or tampered.
    """
    parts = detached_jws_header.strip().split(".")
    if len(parts) != 3 or parts[1] != "":
        # Also check if passed as header..signature (split yields 3 parts with empty middle)
        raise InvalidSignatureError(
            f"Invalid ReBIT detached JWS format. Expected 'header..signature', got {len(parts)} parts."
        )

    header_b64, _, signature_b64 = parts

    try:
        header_bytes = _base64url_decode(header_b64)
        header = json.loads(header_bytes.decode("utf-8"))
        if header.get("alg") != "RS256":
            raise InvalidSignatureError(f"Unsupported algorithm '{header.get('alg')}'. ReBIT requires RS256.")

        sig_bytes = _base64url_decode(signature_b64)
    except Exception as exc:
        raise InvalidSignatureError(f"Failed to decode detached JWS tokens: {exc}") from exc

    if isinstance(aa_public_key_pem, str):
        key_bytes = aa_public_key_pem.encode("utf-8")
    else:
        key_bytes = aa_public_key_pem

    try:
        pub_key = serialization.load_pem_public_key(key_bytes, backend=default_backend())
        signing_input = header_b64.encode("ascii") + b"." + raw_payload_bytes
        pub_key.verify(sig_bytes, signing_input, padding.PKCS1v15(), hashes.SHA256())
        return True
    except InvalidSignature as exc:
        raise InvalidSignatureError("ReBIT detached JWS signature verification failed: signature mismatch.") from exc
    except Exception as exc:
        raise InvalidSignatureError(f"ReBIT detached JWS cryptographic verification failed: {exc}") from exc


class SovereignConsentGate:
    """Zero-Trust Consent Gate for SACP v0.2.

    Validates:
    1. RS256 JWS signature (both embedded compact and ReBIT detached JWS).
    2. Zero-retention enforcement (strictly blocks ConsentMode.STORE).
    3. UTC temporal validity window (consentStart <= now <= consentExpiry).
    4. Exact purpose code authorization.
    5. Financial Information (FI) type scope containment.
    6. Live revocation status check (supporting dynamic webhook revocations).
    7. ReBIT interoperability headers (x-interoperability-version, aa-entity-id, fiu-entity-id).
    """

    def __init__(
        self,
        revocation_checker: Optional[Callable[[str], bool]] = None,
    ) -> None:
        """Initialize SovereignConsentGate.

        Args:
            revocation_checker: Optional callable taking consentId and returning True if revoked.
        """
        self._revocation_checker = revocation_checker
        self._revoked_consent_ids: Set[str] = set()
        self._lock = threading.Lock()

    def revoke_consent_live(self, consent_id: str) -> None:
        """Mark a consent ID as revoked in the live registry (called by AA webhooks)."""
        with self._lock:
            self._revoked_consent_ids.add(consent_id)

    def is_consent_revoked(self, consent_id: str) -> bool:
        """Check if consent has been revoked either locally or via revocation checker."""
        with self._lock:
            if consent_id in self._revoked_consent_ids:
                return True
        if self._revocation_checker and self._revocation_checker(consent_id):
            return True
        return False

    def _ensure_utc(self, dt: datetime) -> datetime:
        """Ensure a datetime is timezone-aware and converted to UTC."""
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    def validate_interop_headers(self, headers: Dict[str, str]) -> bool:
        """Validate ReBIT interoperability headers."""
        norm = {k.lower(): v for k, v in headers.items()}
        interop_ver = norm.get("x-interoperability-version")
        if interop_ver and not (interop_ver.startswith("2.") or interop_ver == "2.0.0"):
            raise RebitInteropHeaderError(
                f"Incompatible ReBIT interoperability version: {interop_ver}. Expected v2.x."
            )
        return True

    def verify_jws_signature(
        self,
        signed_consent_jws: str,
        expected_consent_id: str,
        aa_public_key_pem: Union[str, bytes],
    ) -> dict:
        """Verify standard embedded RS256 JWS signature using the AA's public key."""
        try:
            if isinstance(aa_public_key_pem, str):
                key_bytes = aa_public_key_pem.encode("utf-8")
            else:
                key_bytes = aa_public_key_pem

            payload = jwt.decode(
                signed_consent_jws,
                key=key_bytes,
                algorithms=["RS256"],
                options={"verify_signature": True, "verify_exp": False},
            )
        except (jwt.PyJWTError, ValueError, Exception) as exc:
            raise InvalidSignatureError(f"RS256 JWS signature verification failed: {exc}") from exc

        token_consent_id = payload.get("consentId") or payload.get("sub")
        if token_consent_id != expected_consent_id:
            raise InvalidSignatureError(
                f"JWS payload consent ID '{token_consent_id}' does not match artefact ID '{expected_consent_id}'."
            )

        return payload

    def enforce_policy(
        self,
        artefact: RebitConsentArtefact,
        aa_public_key_pem: Union[str, bytes],
        requested_purpose: str,
        requested_fi_type: Union[FIType, str] = "DEPOSIT",
        is_revoked_live: bool = False,
        raw_payload_bytes: Optional[bytes] = None,
        detached_jws: Optional[str] = None,
        interop_headers: Optional[Dict[str, str]] = None,
        current_utc: Optional[datetime] = None,
    ) -> bool:
        """Enforces all sovereign security policies against the consent artefact.

        Supports both standard embedded JWS in artefact.signedConsent, or detached JWS
        via detached_jws + raw_payload_bytes as per ReBIT v2.0+ specifications.

        Args:
            artefact: The RebitConsentArtefact instance.
            aa_public_key_pem: Account Aggregator's RSA public key (PEM).
            requested_purpose: Purpose code requested (e.g. '101').
            requested_fi_type: The FI type being requested (e.g. 'DEPOSIT').
            is_revoked_live: Live revocation check boolean.
            raw_payload_bytes: Optional raw bytes if verifying detached JWS.
            detached_jws: Optional detached JWS header string (header..signature).
            interop_headers: Optional ReBIT interoperability headers.
            current_utc: Optional current UTC time for deterministic testing.

        Returns:
            bool: True if all policies pass.
        """
        # 1. Check live revocation
        if is_revoked_live or self.is_consent_revoked(artefact.consentId):
            raise ConsentRevokedError(f"Consent '{artefact.consentId}' rejected by live revocation check.")

        # 2. Artefact status check
        if artefact.status == ConsentStatus.REVOKED:
            raise ConsentRevokedError(f"Consent '{artefact.consentId}' is marked as REVOKED.")

        # 3. Interoperability header validation (if provided)
        if interop_headers:
            self.validate_interop_headers(interop_headers)

        # 4. Cryptographic signature verification (Detached or Embedded)
        if detached_jws and raw_payload_bytes is not None:
            verify_detached_jws(
                raw_payload_bytes=raw_payload_bytes,
                detached_jws_header=detached_jws,
                aa_public_key_pem=aa_public_key_pem,
            )
        else:
            self.verify_jws_signature(
                signed_consent_jws=artefact.signedConsent,
                expected_consent_id=artefact.consentId,
                aa_public_key_pem=aa_public_key_pem,
            )

        detail = artefact.consentDetail

        # 5. Strict block on STORE mode (Zero-Retention Sovereign Mandate)
        if detail.consentMode == ConsentMode.STORE:
            raise StoreConsentModeBlockedError(
                "ConsentMode 'STORE' is strictly prohibited under SACP zero-retention rules. "
                "Agents may only access financial context via ephemeral compute (VIEW/QUERY)."
            )

        # 6. Temporal validity window check (UTC)
        now = self._ensure_utc(current_utc or datetime.now(timezone.utc))
        start_utc = self._ensure_utc(detail.consentStart)
        expiry_utc = self._ensure_utc(detail.consentExpiry)

        if now > expiry_utc:
            raise ConsentExpiredError(
                f"Consent expired at {expiry_utc.isoformat()} (Current time: {now.isoformat()})."
            )

        if now < start_utc:
            raise ConsentNotYetValidError(
                f"Consent not yet valid until {start_utc.isoformat()} (Current time: {now.isoformat()})."
            )

        # 7. Purpose code validation
        if detail.purpose.code != requested_purpose:
            raise InvalidPurposeError(
                f"Requested purpose code '{requested_purpose}' does not match consented purpose '{detail.purpose.code}'."
            )

        # 8. FI type scope check
        normalized_fi_type = (
            requested_fi_type if isinstance(requested_fi_type, FIType) else FIType(requested_fi_type)
        )
        if normalized_fi_type not in detail.fiTypes:
            raise FITypeScopeViolationError(
                f"Requested FI type '{normalized_fi_type.value}' is not within consented fiTypes: "
                f"{[t.value for t in detail.fiTypes]}."
            )

        return True

    def evaluate(
        self,
        artefact: RebitConsentArtefact,
        aa_public_key_pem: Union[str, bytes],
        requested_purpose: str,
        requested_fi_type: Union[FIType, str] = "DEPOSIT",
        is_revoked_live: bool = False,
        current_utc: Optional[datetime] = None,
    ) -> bool:
        """Alias for enforce_policy for backward compatibility."""
        return self.enforce_policy(
            artefact=artefact,
            aa_public_key_pem=aa_public_key_pem,
            requested_purpose=requested_purpose,
            requested_fi_type=requested_fi_type,
            is_revoked_live=is_revoked_live,
            current_utc=current_utc,
        )
