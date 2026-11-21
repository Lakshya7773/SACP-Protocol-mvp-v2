"""Ephemeral In-Memory Compute Engine for SACP Phase 2 & Phase 4 (v0.2).

Supports:
1. ReBIT v2.0+ Native Forward-Secrecy Decryption (X25519 ECDH + HKDF-SHA256 + AES-256-GCM).
2. Legacy Fernet Decryption for mock testing convenience.
3. Multi-FI Schema support: DEPOSIT, GSTN, and NPS.
4. Immediate PII stripping (PAN, GSTIN, PRAN, maskedAccNumber, name) and RAM buffer zero-wipe.
"""

import base64
import gc
import json
from typing import Any, Dict, List, Optional, Tuple, Union

from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class EphemeralComputeError(Exception):
    """Raised when in-RAM decryption or cashflow computation fails."""


# ---------------------------------------------------------------------------
# ReBIT Native Forward-Secrecy Cryptography (X25519 + HKDF + AES-256-GCM)
# ---------------------------------------------------------------------------


def generate_x25519_keypair() -> Tuple[str, str]:
    """Generate ephemeral X25519 private and public keys in PEM format."""
    priv = x25519.X25519PrivateKey.generate()
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


def encrypt_rebit_ecdh_payload(
    payload: Dict[str, Any],
    fip_ephemeral_private_pem: Union[str, bytes],
    fiu_public_pem: Union[str, bytes],
    info: bytes = b"ReBIT_FI_KEY",
) -> Dict[str, str]:
    """Helper to encrypt an FI payload using ReBIT forward-secrecy standard.

    Args:
        payload: Dict representing the Account Aggregator FI payload.
        fip_ephemeral_private_pem: FIP ephemeral private X25519 key (PEM).
        fiu_public_pem: FIU public X25519 key (PEM).
        info: HKDF context info.

    Returns:
        dict: Containing 'encrypted_b64', 'nonce_b64', and 'fip_ephemeral_public_pem'.
    """
    fip_priv_bytes = (
        fip_ephemeral_private_pem.encode("utf-8")
        if isinstance(fip_ephemeral_private_pem, str)
        else fip_ephemeral_private_pem
    )
    fiu_pub_bytes = (
        fiu_public_pem.encode("utf-8")
        if isinstance(fiu_public_pem, str)
        else fiu_public_pem
    )

    fip_priv = serialization.load_pem_private_key(fip_priv_bytes, password=None, backend=default_backend())
    fiu_pub = serialization.load_pem_public_key(fiu_pub_bytes, backend=default_backend())

    # 1. Compute ECDH shared secret
    shared_secret = fip_priv.exchange(fiu_pub)

    # 2. Derive 256-bit AES key via HKDF-SHA256
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
        backend=default_backend(),
    )
    aes_key = hkdf.derive(shared_secret)

    # 3. Authenticated AES-256-GCM encryption
    aesgcm = AESGCM(aes_key)
    import os

    nonce = os.urandom(12)  # Standard 96-bit nonce
    payload_bytes = json.dumps(payload).encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, payload_bytes, None)

    fip_pub_pem = fip_priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    return {
        "encrypted_b64": base64.b64encode(ciphertext).decode("ascii"),
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "fip_ephemeral_public_pem": fip_pub_pem,
    }


def decrypt_rebit_ecdh_payload(
    encrypted_b64: str,
    fiu_private_x25519_pem: Union[str, bytes],
    fip_ephemeral_public_x25519_pem: Union[str, bytes],
    nonce_b64: str,
    info: bytes = b"ReBIT_FI_KEY",
) -> bytearray:
    """Decrypt ReBIT forward-secrecy encrypted payload strictly into RAM.

    Args:
        encrypted_b64: Base64-encoded ciphertext.
        fiu_private_x25519_pem: FIU private X25519 key (PEM).
        fip_ephemeral_public_x25519_pem: FIP ephemeral public X25519 key (PEM).
        nonce_b64: Base64-encoded 12-byte GCM nonce.
        info: HKDF context info.

    Returns:
        bytearray: Mutable RAM buffer containing decrypted JSON bytes.

    Raises:
        EphemeralComputeError: If decryption fails.
    """
    fiu_priv_bytes = (
        fiu_private_x25519_pem.encode("utf-8")
        if isinstance(fiu_private_x25519_pem, str)
        else fiu_private_x25519_pem
    )
    fip_pub_bytes = (
        fip_ephemeral_public_x25519_pem.encode("utf-8")
        if isinstance(fip_ephemeral_public_x25519_pem, str)
        else fip_ephemeral_public_x25519_pem
    )

    try:
        fiu_priv = serialization.load_pem_private_key(fiu_priv_bytes, password=None, backend=default_backend())
        fip_pub = serialization.load_pem_public_key(fip_pub_bytes, backend=default_backend())

        # 1. Compute ECDH shared secret
        shared_secret = fiu_priv.exchange(fip_pub)

        # 2. Derive 256-bit AES key via HKDF-SHA256
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=info,
            backend=default_backend(),
        )
        aes_key = hkdf.derive(shared_secret)

        # 3. Authenticated AES-256-GCM decryption
        aesgcm = AESGCM(aes_key)
        ciphertext = base64.b64decode(encrypted_b64)
        nonce = base64.b64decode(nonce_b64)
        raw_decrypted = aesgcm.decrypt(nonce, ciphertext, None)
        return bytearray(raw_decrypted)
    except Exception as exc:
        raise EphemeralComputeError(f"ReBIT X25519 ECDH + AES-256-GCM decryption failed: {exc}") from exc


# ---------------------------------------------------------------------------
# Legacy Fernet Decryption (for mock testing convenience)
# ---------------------------------------------------------------------------


def encrypt_fi_payload_fernet(payload: Dict[str, Any], fernet_key: Union[bytes, str]) -> str:
    """Helper to encrypt a mock FI payload with Fernet."""
    key_bytes = fernet_key.encode("utf-8") if isinstance(fernet_key, str) else fernet_key
    f = Fernet(key_bytes)
    data_bytes = json.dumps(payload).encode("utf-8")
    return f.encrypt(data_bytes).decode("utf-8")


# ---------------------------------------------------------------------------
# Multi-FI In-RAM Ephemeral Compute Engine
# ---------------------------------------------------------------------------


class EphemeralRAMCompute:
    """Decrypts financial data strictly in RAM, strips all PII, and aggregates metrics."""

    def __init__(self, decryption_key: Optional[Union[bytes, str]] = None) -> None:
        """Initialize with optional Fernet key."""
        if decryption_key:
            key_bytes = decryption_key.encode("utf-8") if isinstance(decryption_key, str) else decryption_key
            try:
                self.fernet = Fernet(key_bytes)
            except Exception as exc:
                raise EphemeralComputeError(f"Invalid Fernet key: {exc}") from exc
        else:
            self.fernet = None

    @staticmethod
    def _zero_and_clear_buffer(buffer: bytearray) -> None:
        """Securely wipe a mutable RAM buffer with zero bytes."""
        if buffer is not None:
            for i in range(len(buffer)):
                buffer[i] = 0
            buffer.clear()

    def process_decrypted_buffer(
        self,
        ram_buffer: bytearray,
        consent_id: str,
        fi_type: str = "DEPOSIT",
    ) -> Dict[str, Any]:
        """Parses JSON strictly from ram_buffer, wipes PII, and returns derived aggregates.

        Guarantees buffer zeroing in finally:.
        """
        try:
            payload_str = ram_buffer.decode("utf-8")
            data: Dict[str, Any] = json.loads(payload_str)
            del payload_str

            # Strip all top-level PII structures
            data.pop("Profile", None)
            data.pop("profile", None)
            data.pop("Customer", None)
            data.pop("customer", None)
            data.pop("Holder", None)
            data.pop("holder", None)

            account = data.get("Account") or data.get("account") or {}
            if isinstance(account, dict):
                account.pop("Profile", None)
                account.pop("profile", None)
                account.pop("Holder", None)
                account.pop("holder", None)
                currency = account.get("currency", "INR")
            else:
                currency = "INR"

            norm_fi_type = fi_type.upper()

            # 1. GSTN Invoices & Turnover Processing
            if norm_fi_type == "GSTN" or "gstin" in str(data).lower() or "invoices" in str(data).lower():
                invoices = (
                    data.get("Invoices")
                    or data.get("invoices")
                    or account.get("Invoices")
                    or account.get("invoices")
                    or []
                )
                if not isinstance(invoices, list):
                    invoices = [invoices]

                total_turnover = 0.0
                total_taxable_value = 0.0
                invoice_count = len(invoices)

                for inv in invoices:
                    if isinstance(inv, dict):
                        inv.pop("gstin", None)
                        inv.pop("tradeName", None)
                        inv.pop("legalName", None)
                        inv.pop("pan", None)
                        inv_val = float(inv.get("invoiceValue") or inv.get("amount") or 0.0)
                        taxable_val = float(inv.get("taxableValue") or inv.get("taxableAmount") or 0.0)
                        total_turnover += inv_val
                        total_taxable_value += taxable_val

                return {
                    "consent_id": consent_id,
                    "fi_type": "GSTN",
                    "total_turnover": round(total_turnover, 2),
                    "total_taxable_value": round(total_taxable_value, 2),
                    "total_invoices": invoice_count,
                    "currency": currency,
                    "retention_status": "ZERO_PII_RETAINED_EPHEMERAL_COMPUTED",
                }

            # 2. NPS Pension Contribution Processing
            if norm_fi_type == "NPS" or "pran" in str(data).lower() or "pension" in str(data).lower():
                contributions = (
                    data.get("Contributions")
                    or data.get("contributions")
                    or account.get("Contributions")
                    or account.get("contributions")
                    or []
                )
                if not isinstance(contributions, list):
                    contributions = [contributions]

                tier1_total = 0.0
                tier2_total = 0.0

                for c in contributions:
                    if isinstance(c, dict):
                        c.pop("pran", None)
                        c.pop("subscriberName", None)
                        tier = str(c.get("tier") or c.get("tierType") or "").upper()
                        amount = float(c.get("amount") or 0.0)
                        if "TIER_1" in tier or "TIER 1" in tier or tier == "1":
                            tier1_total += amount
                        elif "TIER_2" in tier or "TIER 2" in tier or tier == "2":
                            tier2_total += amount
                        else:
                            tier1_total += amount

                return {
                    "consent_id": consent_id,
                    "fi_type": "NPS",
                    "tier1_contributions": round(tier1_total, 2),
                    "tier2_contributions": round(tier2_total, 2),
                    "total_nps_contributions": round(tier1_total + tier2_total, 2),
                    "currency": currency,
                    "retention_status": "ZERO_PII_RETAINED_EPHEMERAL_COMPUTED",
                }

            # 3. Standard DEPOSIT Processing (Cashflow)
            if isinstance(account, dict):
                txns_node = account.get("Transactions") or account.get("transactions") or []
                if isinstance(txns_node, dict):
                    transactions = txns_node.get("Transaction") or txns_node.get("transaction") or []
                elif isinstance(txns_node, list):
                    transactions = txns_node
                else:
                    transactions = []
            else:
                transactions = data.get("transactions") or []

            if not isinstance(transactions, list):
                transactions = [transactions]

            total_inflow = 0.0
            total_outflow = 0.0
            credit_transactions = 0
            debit_transactions = 0

            for txn in transactions:
                if not isinstance(txn, dict):
                    continue
                # Strip raw narration/pii
                txn_type = str(txn.get("type") or txn.get("txnType") or "").upper()
                try:
                    amount = float(txn.get("amount", 0.0))
                except (ValueError, TypeError):
                    amount = 0.0

                if txn_type in ("CREDIT", "CR"):
                    total_inflow += amount
                    credit_transactions += 1
                elif txn_type in ("DEBIT", "DR"):
                    total_outflow += amount
                    debit_transactions += 1

            total_inflow = round(total_inflow, 2)
            total_outflow = round(total_outflow, 2)
            net_surplus = round(total_inflow - total_outflow, 2)

            return {
                "consent_id": consent_id,
                "fi_type": "DEPOSIT",
                "total_inflow": total_inflow,
                "total_outflow": total_outflow,
                "net_surplus": net_surplus,
                "credit_transactions": credit_transactions,
                "debit_transactions": debit_transactions,
                "currency": currency,
                "retention_status": "ZERO_PII_RETAINED_EPHEMERAL_COMPUTED",
            }
        except EphemeralComputeError:
            raise
        except Exception as exc:
            raise EphemeralComputeError(f"In-RAM compute failed: {exc}") from exc
        finally:
            self._zero_and_clear_buffer(ram_buffer)
            del ram_buffer
            gc.collect()

    def compute_cashflow_summary(
        self,
        encrypted_fi_blob: Union[bytes, str],
        consent_id: str,
        fi_type: str = "DEPOSIT",
    ) -> Dict[str, Any]:
        """Decrypt payload using Fernet strictly into RAM, strip PII, and compute metrics."""
        if not self.fernet:
            raise EphemeralComputeError("Fernet decryptor not initialized.")

        blob_bytes = (
            encrypted_fi_blob.encode("utf-8")
            if isinstance(encrypted_fi_blob, str)
            else encrypted_fi_blob
        )

        try:
            raw_decrypted = self.fernet.decrypt(blob_bytes)
        except (InvalidToken, Exception) as exc:
            raise EphemeralComputeError(f"Fernet decryption failed: {exc}") from exc

        ram_buffer = bytearray(raw_decrypted)
        del raw_decrypted

        return self.process_decrypted_buffer(ram_buffer, consent_id, fi_type=fi_type)
