import httpx
import time
import datetime
import json
import logging
from typing import Dict, Any, Optional
from ..common.config import KEYCLOAK_CFG, SEQ_CFG
from ..common.const import DEFAULT_REALM, DEFAULT_REQUEST_TIMEOUT

logger = logging.getLogger(__name__)


class SeqLogger:
    """Minimal CLEF logger that POSTs structured events to Seq."""

    def __init__(self, seq_url: str, api_key: Optional[str], app_name: str = "keycloak-mcp"):
        self.ingest_url = f"{seq_url.rstrip('/')}/api/events/raw?clef"
        self.api_key = api_key
        self.app_name = app_name
        self._client: Optional[httpx.AsyncClient] = None

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=5)
        return self._client

    async def emit(self, level: str, message_template: str, **props):
        """Send a single CLEF event to Seq."""
        if not self.api_key:
            return
        event = {
            "@t": datetime.datetime.utcnow().isoformat() + "Z",
            "@l": level,
            "@mt": message_template,
            "Application": self.app_name,
            **props,
        }
        try:
            client = await self._ensure_client()
            headers = {"X-Seq-ApiKey": self.api_key, "Content-Type": "application/vnd.serilog.clef"}
            response = await client.post(self.ingest_url, content=json.dumps(event), headers=headers)
            if response.status_code >= 400:
                logger.warning(f"SeqLogger: Seq returned {response.status_code} for event: {message_template}")
        except Exception as e:
            logger.warning(f"SeqLogger: Failed to send event to Seq: {e}")

    async def close(self):
        if self._client:
            await self._client.aclose()
            self._client = None


class KeycloakClient:
    def __init__(self):
        self.server_url = KEYCLOAK_CFG["server_url"]
        self.username = KEYCLOAK_CFG["username"]
        self.password = KEYCLOAK_CFG["password"]
        self.realm_name = (
            KEYCLOAK_CFG["realm_name"] if KEYCLOAK_CFG["realm_name"] else DEFAULT_REALM
        )
        self.client_id = KEYCLOAK_CFG["client_id"]
        self.client_secret = KEYCLOAK_CFG["client_secret"]
        self.token = None
        self.refresh_token = None
        self._client = None
        self._seq = SeqLogger(SEQ_CFG["url"], SEQ_CFG["api_key"])

    async def _ensure_client(self):
        """Ensure httpx async client exists"""
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=DEFAULT_REQUEST_TIMEOUT)
        return self._client

    async def _get_token(self) -> str:
        """Get access token using client credentials flow"""
        token_url = f"{self.server_url}/realms/{self.realm_name}/protocol/openid-connect/token"

        data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }

        client = await self._ensure_client()
        t0 = time.monotonic()
        try:
            response = await client.post(token_url, data=data)
            response.raise_for_status()
            elapsed = int((time.monotonic() - t0) * 1000)
            token_data = response.json()
            self.token = token_data["access_token"]
            self.refresh_token = token_data.get("refresh_token")
            await self._seq.emit("Information", "Keycloak token acquired for {ClientId} in {ElapsedMs}ms",
                ClientId=self.client_id, ElapsedMs=elapsed, Realm=self.realm_name)
            return self.token
        except Exception as e:
            elapsed = int((time.monotonic() - t0) * 1000)
            await self._seq.emit("Error", "Keycloak token acquisition failed for {ClientId}: {Error}",
                ClientId=self.client_id, ElapsedMs=elapsed, Realm=self.realm_name, Error=str(e))
            raise

    async def _get_headers(self) -> Dict[str, str]:
        """Get headers with authorization token"""
        if not self.token:
            await self._get_token()

        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }

    async def _make_request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict] = None,
        params: Optional[Dict] = None,
        skip_realm: bool = False,
        realm: Optional[str] = None,
    ) -> Any:
        """Make authenticated request to Keycloak API"""
        target_realm = None
        if skip_realm:
            url = f"{self.server_url}/admin{endpoint}"
        else:
            # Use provided realm or fall back to configured realm
            target_realm = realm if realm is not None else self.realm_name
            url = f"{self.server_url}/admin/realms/{target_realm}{endpoint}"

        t0 = time.monotonic()
        try:
            client = await self._ensure_client()
            headers = await self._get_headers()

            response = await client.request(
                method=method,
                url=url,
                headers=headers,
                json=data,
                params=params,
            )

            # If token expired, refresh and retry
            if response.status_code == 401:
                await self._get_token()
                headers = await self._get_headers()
                response = await client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    json=data,
                    params=params,
                )

            response.raise_for_status()
            elapsed = int((time.monotonic() - t0) * 1000)
            await self._seq.emit(
                "Information", "{Method} {Endpoint} responded {StatusCode} in {ElapsedMs}ms",
                Method=method, Endpoint=endpoint, StatusCode=response.status_code,
                ElapsedMs=elapsed, Realm=target_realm if not skip_realm else None,
            )

            if response.content:
                return response.json()
            return None

        except httpx.RequestError as e:
            elapsed = int((time.monotonic() - t0) * 1000)
            await self._seq.emit(
                "Error", "{Method} {Endpoint} request failed: {Error}",
                Method=method, Endpoint=endpoint, ElapsedMs=elapsed, Error=str(e),
            )
            raise Exception(f"Keycloak API request failed: {str(e)}")
        except httpx.HTTPStatusError as e:
            elapsed = int((time.monotonic() - t0) * 1000)
            await self._seq.emit(
                "Error", "{Method} {Endpoint} returned {StatusCode}: {Error}",
                Method=method, Endpoint=endpoint, StatusCode=e.response.status_code,
                ElapsedMs=elapsed, Error=str(e),
            )
            raise

    async def close(self):
        """Close the httpx client"""
        if self._client:
            await self._client.aclose()
            self._client = None
        await self._seq.close()
