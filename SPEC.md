# Sovereign Agentic Context Protocol (SACP) v0.2 Specification

**Status:** Active Standard / Production Upgrade  
**Version:** 0.2.0  
**Target Architecture:** Model Context Protocol (MCP) Streamable HTTP  
**Regulatory Anchor:** Reserve Bank of India (RBI) / ReBIT Account Aggregator Technical Standards v2.0+, Digital Personal Data Protection (DPDP) Act, 2023  
**License:** Apache-2.0  

---

## 1. Abstract & Motivation

Autonomous AI agents (such as automated credit underwriting models, wealth managers, and algorithmic advisors) require high-fidelity financial context to make consequential decisions. Traditional data integration models either:
1. Transfer raw consumer banking records to the agent (leaking persistent customer PII, account numbers, and detailed transaction lines), or
2. Rely on proprietary APIs lacking cryptographic consent verification or immutable audit trails.

The **Sovereign Agentic Context Protocol (SACP)** defines an open, zero-retention, cryptographically verifiable protocol gateway. Operating over the Model Context Protocol (MCP), SACP maps official ReBIT Account Aggregator (AA) consent artefacts onto agentic tools, decrypts financial payloads strictly in RAM using forward-secrecy cryptography, strips all PII, computes deterministic domain aggregates, and seals tamper-evident SHA-256 hash-chained receipts into an immutable DPDP audit ledger.

---

## 2. Inviolable Protocol Invariants

SACP enforces five sovereign security policies:

| Invariant | Technical Enforcement | Violation Result |
| :--- | :--- | :--- |
| **Zero Raw Retention** | Mandatory rejection of `ConsentMode.STORE`. Only `VIEW`, `QUERY`, or `STREAM` are permitted. | `StoreConsentModeBlockedError` (`DENIED_STORE_MODE_BLOCKED`) |
| **Instant Citizen Revocation** | Live citizen revocation registry updated via AA webhook callbacks (`POST /Consent/Notification`) and live parameters. | `ConsentRevokedError` (`DENIED_CONSENT_REVOKED`) |
| **Purpose Limitation** | Agent query purpose code must strictly match consented `purpose.code` (DPDP Act Sec 6). | `InvalidPurposeError` (`DENIED_PURPOSE_MISMATCH`) |
| **Forward-Secrecy RAM Hygiene** | In-memory `X25519 ECDH + AES-256-GCM` decryption; PII stripped immediately; mutable RAM buffers overwritten with `0x00` + `gc.collect()`. | Guaranteed zero PII persistence or memory leakage |
| **Cryptographic Tamper Evidence**| Every authorization and denial is sealed into an append-only SHA-256 hash-chained ledger. | Inability to alter, reorder, or delete audit events undetected |

---

## 3. Cryptographic Pipeline (v0.2)

### 3.1 ReBIT Detached JWS Signature Verification
ReBIT Technical Standards v2.0+ utilize detached JWS signatures transmitted in the `x-jws-signature` header:
* **Format:** `base64url(header)..base64url(signature)`
* **Signing Input:** `ASCII(header_b64) + b"." + raw_payload_bytes`
* **Algorithm:** RS256 (RSA PKCS#1 v1.5 with SHA-256).
* The gateway recomputes the detached digest over the exact raw payload bytes and verifies it against the Account Aggregator's public key before parsing the artefact.

### 3.2 Forward-Secrecy Key Agreement & Ephemeral Decryption
To guarantee end-to-end forward secrecy:
1. **Key Agreement:** The Financial Information User (FIU) provides a static or session public key $K_{\text{FIU}}^{\text{pub}}$ (Curve25519). The Financial Information Provider (FIP) generates an ephemeral private/public keypair $(k_{\text{FIP}}^{\text{eph}}, K_{\text{FIP}}^{\text{eph}})$.
2. **Shared Secret:** Both parties compute the shared secret:
   $$S = \text{X25519}(k_{\text{FIU}}^{\text{priv}}, K_{\text{FIP}}^{\text{eph}}) = \text{X25519}(k_{\text{FIP}}^{\text{eph}}, K_{\text{FIU}}^{\text{pub}})$$
3. **Key Derivation:** HKDF-SHA256 derives a 256-bit symmetric key:
   $$\text{AES\_KEY} = \text{HKDF-SHA256}(S, \text{salt}=\text{None}, \text{info}=b\text{"ReBIT\_FI\_KEY"}, \text{length}=32)$$
4. **Authenticated Decryption:** The ciphertext is decrypted in RAM using `AES-256-GCM` with a 96-bit nonce.
5. **Memory Zero-Wiping:** Decrypted data is held in a mutable `bytearray`. After processing, the buffer is overwritten with `0x00` in a guaranteed `finally:` block.

---

## 4. Multi-FI Schema Processing & PII Stripping

SACP v0.2 provides multi-FI schema support across ReBIT v2.0.0 definitions:

### 4.1 DEPOSIT (Bank Accounts)
* **Stripped PII:** `Profile`, `Holders`, `Holder`, `name`, `pan`, `maskedAccNumber`, `mobile`, `email`.
* **Computed Aggregates:**
  $$\text{total\_inflow} = \sum \text{amount}_{\text{CREDIT}}$$
  $$\text{total\_outflow} = \sum \text{amount}_{\text{DEBIT}}$$
  $$\text{net\_surplus} = \text{total\_inflow} - \text{total\_outflow}$$
  $$\text{credit\_transactions}, \text{debit\_transactions}$$

### 4.2 GSTN (Goods & Services Tax Network)
* **Stripped PII:** `gstin`, `pan`, `legalName`, `tradeName`.
* **Computed Aggregates:**
  $$\text{total\_turnover} = \sum \text{invoiceValue}$$
  $$\text{total\_taxable\_value} = \sum \text{taxableValue}$$
  $$\text{total\_invoices}$$

### 4.3 NPS (National Pension System)
* **Stripped PII:** `pran`, `pan`, `subscriberName`.
* **Computed Aggregates:**
  $$\text{tier1\_contributions} = \sum \text{amount}_{\text{TIER\_1}}$$
  $$\text{tier2\_contributions} = \sum \text{amount}_{\text{TIER\_2}}$$
  $$\text{total\_nps\_contributions} = \text{tier1\_contributions} + \text{tier2\_contributions}$$

---

## 5. Account Aggregator Sandbox & Webhook Adapters

### 5.1 Outgoing AA Client (`AASandboxClient`)
* `create_consent_request(consent_detail)`: `POST /Consent`
* `get_consent_status(consent_handle)`: `GET /Consent/handle/{consentHandle}`
* `request_fi_data(consent_id, fiu_x25519_pub, date_range)`: `POST /FI/request`
* `fetch_fi_data(session_id)`: `GET /FI/fetch/{sessionId}`

### 5.2 Incoming Webhook Endpoints
* **`POST /Consent/Notification`**: Receives citizen status notifications from AA apps (OneMoney, Finvu, Anumati, Setu). If status is `REVOKED`, `PAUSED`, `EXPIRED`, or `REJECTED`, the gateway instantly registers the revocation and blocks any subsequent compute queries.
* **`POST /FI/Notification`**: Handles asynchronous data readiness notifications from the AA ecosystem.

---

## 6. Tamper-Evident DPDP Audit Ledger

Compliant with DPDP Act 2023 Section 6 and Section 8 audit requirements, every evaluation creates a record in `dpdp_audit_ledger`:

$$\text{entry\_hash} = \text{SHA256}(\text{CanonicalJSON}(\text{seq\_id}, \text{timestamp}, \text{consent\_id}, \text{txnid}, \dots, \text{prev\_hash}))$$

The ledger maintains an unbroken cryptographic hash chain from row 1 ($\text{prev\_hash} = \text{"GENESIS\_0000000000000000"}$) through row $N$, verified via `verify_chain_integrity()`.

---

## 7. Model Context Protocol (MCP) Interface

### 7.1 Server Configuration
* **Transport:** Streamable HTTP (`MCP 2.0+` over ASGI / Starlette).
* **Endpoint Path:** `/mcp`
* **Port:** `8000`
* **Authentication:** Bearer token via `Authorization: Bearer <SACP_CLIENT_API_KEY>` (webhooks exempted).

### 7.2 Tool: `query_consented_financial_context`
* **Parameters:**
  * `consent_artefact_json` (dict | str, required): Serialized `RebitConsentArtefact`.
  * `encrypted_fi_payload_b64` (str, required): Encrypted banking/GSTN/NPS payload.
  * `requested_purpose_code` (str, required): Purpose code (e.g. `"101"`).
  * `requested_fi_type` (str, optional, default `"DEPOSIT"`): FI type (`DEPOSIT`, `GSTN`, `NPS`).
  * `is_revoked_live` (bool, optional, default `False`): Live revocation flag.
  * `agent_id` (str, optional, default `"external-ai-agent"`): Requesting agent ID.
  * `detached_jws` (str, optional): Detached JWS header string (`header..signature`).
  * `fip_ephemeral_public_key_pem` (str, optional): FIP ephemeral X25519 public key.
  * `nonce_b64` (str, optional): Base64 12-byte AES-GCM nonce.
  * `fiu_private_key_pem` (str, optional): FIU private X25519 key.
  * `interop_headers` (dict, optional): ReBIT interoperability headers.

### 7.3 Tool: `verify_sovereign_audit_trail`
* **Parameters:** None.
* **Returns:**
  ```json
  {
    "chain_valid": true,
    "total_events": 16,
    "message": "Chain integrity verified across 16 entries.",
    "compliance": "DPDP_ACT_2023_TAMPER_EVIDENT"
  }
  ```
