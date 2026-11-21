"""Account Aggregator Sandbox Client and Webhook Adapters (v0.2).

Provides an asynchronous HTTP client for interacting with Sahamati/ReBIT
AA Sandbox endpoints, and a FastAPI webhook router for live citizen revocation
and FI notifications.
"""

from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, Optional, Union
import uuid

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route, Router
import httpx

from app.core.consent_gate import SovereignConsentGate, sign_detached_jws
from app.ledger.audit_ledger import DPDPAuditLedger
from app.models.rebit_schema import ConsentDetail

logger = logging.getLogger("sacp.aa_sandbox")


class AASandboxError(Exception):
    """Exception raised for Account Aggregator Sandbox API failures."""


class AASandboxClient:
    """Asynchronous client for interacting with Sahamati / ReBIT AA Sandboxes."""

    def __init__(
        self,
        base_url: str = "https://api-sandbox.sahamati.org.in",
        client_id: str = "SACP-FIU-SANDBOX",
        client_secret: Optional[str] = None,
        fiu_entity_id: str = "SACP-FIU-APP",
        aa_entity_id: str = "AA-SANDBOX",
        fiu_private_key_pem: Optional[str] = None,
        mock_mode: bool = False,
        timeout_seconds: float = 10.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.fiu_entity_id = fiu_entity_id
        self.aa_entity_id = aa_entity_id
        self.fiu_private_key_pem = fiu_private_key_pem
        self.mock_mode = mock_mode
        self.timeout = timeout_seconds

    def _generate_txnid(self) -> str:
        return str(uuid.uuid4())

    def _now_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _build_headers(
        self,
        raw_body_bytes: bytes,
        txn_id: str,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "x-interoperability-version": "2.0.0",
            "aa-entity-id": self.aa_entity_id,
            "fiu-entity-id": self.fiu_entity_id,
            "client_api_key": self.client_secret or "dev-fiu-sandbox-key",
            "txnid": txn_id,
            "timestamp": self._now_iso(),
        }
        if self.fiu_private_key_pem:
            detached_jws = sign_detached_jws(
                raw_payload_bytes=raw_body_bytes,
                private_key_pem=self.fiu_private_key_pem,
                extra_headers={"fiu_entity_id": self.fiu_entity_id},
            )
            headers["x-jws-signature"] = detached_jws

        if extra_headers:
            headers.update(extra_headers)
        return headers

    async def create_consent_request(
        self,
        consent_detail: Union[ConsentDetail, Dict[str, Any]],
        txn_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Send a consent request to the Account Aggregator (POST /Consent)."""
        txnid = txn_id or self._generate_txnid()
        if hasattr(consent_detail, "model_dump"):
            detail_dict = consent_detail.model_dump(mode="json", by_alias=True)
        else:
            detail_dict = consent_detail
        payload = {
            "ver": "2.0.0",
            "timestamp": self._now_iso(),
            "txnid": txnid,
            "ConsentDetail": detail_dict,
        }
        raw_bytes = json.dumps(payload).encode("utf-8")

        if self.mock_mode:
            consent_handle = f"handle-{uuid.uuid4()}"
            return {
                "ver": "2.0.0",
                "timestamp": self._now_iso(),
                "txnid": txnid,
                "ConsentHandle": consent_handle,
                "status": "PENDING",
            }

        headers = self._build_headers(raw_bytes, txnid)
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                resp = await client.post(
                    f"{self.base_url}/Consent",
                    content=raw_bytes,
                    headers=headers,
                )
                resp.raise_for_status()
                return resp.json()
            except httpx.HTTPError as exc:
                raise AASandboxError(f"AA Sandbox POST /Consent failed: {exc}") from exc

    async def get_consent_status(
        self,
        consent_handle: str,
        txn_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Fetch consent status by consentHandle (GET /Consent/handle/{consentHandle})."""
        txnid = txn_id or self._generate_txnid()
        if self.mock_mode:
            return {
                "ver": "2.0.0",
                "timestamp": self._now_iso(),
                "txnid": txnid,
                "ConsentStatus": {
                    "id": consent_handle,
                    "status": "ACTIVE",
                    "consentId": f"consent-{uuid.uuid4()}",
                },
            }

        headers = self._build_headers(b"", txnid)
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                resp = await client.get(
                    f"{self.base_url}/Consent/handle/{consent_handle}",
                    headers=headers,
                )
                resp.raise_for_status()
                return resp.json()
            except httpx.HTTPError as exc:
                raise AASandboxError(f"AA Sandbox GET /Consent/handle failed: {exc}") from exc

    async def request_fi_data(
        self,
        consent_id: str,
        fiu_x25519_pub_pem: str,
        date_range: Dict[str, str],
        key_material: Optional[Dict[str, Any]] = None,
        txn_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Trigger financial information session request (POST /FI/request)."""
        txnid = txn_id or self._generate_txnid()
        payload = {
            "ver": "2.0.0",
            "timestamp": self._now_iso(),
            "txnid": txnid,
            "FIDataRange": date_range,
            "Consent": {"id": consent_id},
            "KeyMaterial": key_material or {"cryptoAlg": "ECDH", "Key": fiu_x25519_pub_pem},
        }
        raw_bytes = json.dumps(payload).encode("utf-8")

        if self.mock_mode:
            session_id = f"session-{uuid.uuid4()}"
            return {
                "ver": "2.0.0",
                "timestamp": self._now_iso(),
                "txnid": txnid,
                "consentId": consent_id,
                "sessionId": session_id,
            }

        headers = self._build_headers(raw_bytes, txnid)
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                resp = await client.post(
                    f"{self.base_url}/FI/request",
                    content=raw_bytes,
                    headers=headers,
                )
                resp.raise_for_status()
                return resp.json()
            except httpx.HTTPError as exc:
                raise AASandboxError(f"AA Sandbox POST /FI/request failed: {exc}") from exc

    async def fetch_fi_data(
        self,
        session_id: str,
        fip_id: Optional[str] = None,
        txn_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Fetch encrypted financial information data (GET /FI/fetch/{sessionId})."""
        txnid = txn_id or self._generate_txnid()
        if self.mock_mode:
            return {
                "ver": "2.0.0",
                "timestamp": self._now_iso(),
                "txnid": txnid,
                "sessionId": session_id,
                "FI": [],
            }

        headers = self._build_headers(b"", txnid)
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                resp = await client.get(
                    f"{self.base_url}/FI/fetch/{session_id}",
                    headers=headers,
                )
                resp.raise_for_status()
                return resp.json()
            except httpx.HTTPError as exc:
                raise AASandboxError(f"AA Sandbox GET /FI/fetch failed: {exc}") from exc


def create_webhook_router(
    consent_gate: SovereignConsentGate,
    audit_ledger: Optional[DPDPAuditLedger] = None,
) -> Router:
    """Create a Starlette/FastAPI compatible Router configured to handle incoming AA Webhook notifications."""

    async def handle_consent_notification(request: Request) -> JSONResponse:
        """Handle incoming ReBIT Consent Status Notification from AA.

        When a citizen revokes, pauses, or expires consent on any AA app (OneMoney,
        Finvu, Anumati, Setu), this webhook immediately marks it revoked in the
        SovereignConsentGate and logs an audit trail event.
        """
        try:
            body = await request.json()
        except Exception as exc:
            return JSONResponse(
                {"error": f"Invalid JSON payload: {exc}"},
                status_code=400,
            )

        notification = body.get("ConsentStatusNotification", {})
        consent_id = notification.get("consentId")
        consent_status = notification.get("consentStatus", "").upper()
        txnid = body.get("txnid", str(uuid.uuid4()))

        if not consent_id:
            return JSONResponse(
                {"error": "Missing 'consentId' in ConsentStatusNotification"},
                status_code=422,
            )

        logger.info(
            f"Received AA Consent Notification: consent_id={consent_id}, status={consent_status}, txnid={txnid}"
        )

        # Mark revoked on REVOKED, PAUSED, EXPIRED, or REJECTED
        if consent_status in ("REVOKED", "PAUSED", "EXPIRED", "REJECTED"):
            consent_gate.revoke_consent_live(consent_id)

            if audit_ledger:
                try:
                    audit_ledger.record_event(
                        consent_id=consent_id,
                        txnid=txnid,
                        agent_id="aa-webhook-listener",
                        requested_purpose_code="SYSTEM_REVOCATION",
                        requested_fi_type="NOTIFICATION",
                        decision="REVOKED",
                        reason=f"Citizen revoked/paused consent via AA webhook notification: status={consent_status}",
                        output_sha256="NONE",
                    )
                except Exception as audit_err:
                    logger.error(f"Failed to record audit event for webhook revocation: {audit_err}")

        return JSONResponse({
            "ver": body.get("ver", "2.0.0"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "txnid": txnid,
            "status": "OK",
            "response": "SUCCESS",
        })

    async def handle_fi_notification(request: Request) -> JSONResponse:
        """Handle incoming ReBIT FI status notification from AA."""
        try:
            body = await request.json()
        except Exception as exc:
            return JSONResponse(
                {"error": f"Invalid JSON payload: {exc}"},
                status_code=400,
            )

        fi_notification = body.get("FIStatusNotification", {})
        session_id = fi_notification.get("sessionId")
        session_status = fi_notification.get("sessionStatus", "").upper()
        txnid = body.get("txnid", str(uuid.uuid4()))

        logger.info(
            f"Received AA FI Notification: sessionId={session_id}, sessionStatus={session_status}, txnid={txnid}"
        )

        return JSONResponse({
            "ver": body.get("ver", "2.0.0"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "txnid": txnid,
            "status": "OK",
            "response": "SUCCESS",
        })

    return Router(routes=[
        Route("/Consent/Notification", handle_consent_notification, methods=["POST"]),
        Route("/FI/Notification", handle_fi_notification, methods=["POST"]),
    ])
