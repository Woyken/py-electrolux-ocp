from base64 import b64decode
from datetime import datetime, timedelta
from json import loads
from types import TracebackType
from typing import Any, Dict, Optional, Type
from aiohttp import ClientSession

from .urls import (
    appliance_command_url,
    current_user_metadata_url,
    get_appliance_by_id_url,
    get_appliance_capabilities_url,
    get_appliances_info_by_ids_url,
    identity_providers_url,
    list_appliances_url,
    token_url,
)
from .const import (
    API_KEY_ELECTROLUX,
    BRAND_ELECTROLUX,
    CLIENT_SECRET_ELECTROLUX,
)
from .apiModels import (
    ApplianceInfoResponse,
    ApplienceStatusResponse,
    AuthResponse,
    ClientCredTokenResponse,
    UserMetadataResponse,
    UserTokenResponse,
)


class UserToken:
    def __init__(self, token: UserTokenResponse) -> None:
        self.token = token
        self.expiresAt = datetime.now() + timedelta(seconds=token["expiresIn"])

    def should_renew(self):
        return self.expiresAt < (datetime.now() - timedelta(minutes=2))


class ClientToken:
    def __init__(self, token: ClientCredTokenResponse) -> None:
        self.token = token
        self.expires_at = datetime.now() + timedelta(seconds=token["expiresIn"])

    def should_renew(self):
        return self.expires_at < (datetime.now() - timedelta(minutes=2))


def decodeJwt(token: str):
    token_payload = token.split(".")[1]
    token_payload_decoded = str(b64decode(token_payload + "=="), "utf-8")
    payload: dict[str, Any] = loads(token_payload_decoded)
    return payload


class OneAppApiClient:
    def __init__(self, client_session: Optional[ClientSession] = None) -> None:
        self._client_session = client_session
        self._close_session = False

    def _get_session(self):
        if self._client_session is None:
            self._client_session = ClientSession()
            self._close_session = True
        return self._client_session

    def _api_headers_base(self, token: Optional[str]):
        headers = {"x-api-key": API_KEY_ELECTROLUX}
        if token is not None:
            headers = {
                **headers,
                "Authorization": token,
            }
        return headers

    async def login_client_credentials(self, base_url: str):
        """Login using client credentials of the mobile application, used for fetching identity providers urls"""
        req_params = token_url(
            base_url,
            self._api_headers_base(None),
            "client_credentials",
            client_secret=CLIENT_SECRET_ELECTROLUX,
        )

        async with await self._get_session().request(**req_params.__dict__) as response:
            response.raise_for_status()
            token: ClientCredTokenResponse = await response.json()
            return ClientToken(token)

    async def exchange_login_user(self, base_url: str, id_token: str):
        """Exchange external id token to api token"""
        decodedToken = decodeJwt(id_token)
        req_params = token_url(
            base_url,
            {
                **self._api_headers_base(None),
                "Origin-Country-Code": decodedToken["country"],
            },
            "urn:ietf:params:oauth:grant-type:token-exchange",
            id_token=id_token,
        )

        async with await self._get_session().request(**req_params.__dict__) as response:
            response.raise_for_status()
            token: UserTokenResponse = await response.json()
            return UserToken(token)

    async def refresh_token_user(self, base_url: str, refresh_token: str):
        req_params = token_url(
            base_url,
            self._api_headers_base(None),
            "refresh_token",
            refresh_token=refresh_token,
        )

        async with await self._get_session().request(**req_params.__dict__) as response:
            response.raise_for_status()
            newToken: UserTokenResponse = await response.json()
            return UserToken(newToken)

    async def get_identity_providers(
        self, base_url: str, client_cred_token: str, username: str
    ):
        req_params = identity_providers_url(
            base_url,
            {
                **self._api_headers_base(None),
                "Authorization": client_cred_token,
            },
            BRAND_ELECTROLUX,
            username,
        )

        async with await self._get_session().request(**req_params.__dict__) as response:
            response.raise_for_status()
            data: list[AuthResponse] = await response.json()
            return data

    async def get_user_metadata(self, base_url: str, token: str):
        req_params = current_user_metadata_url(base_url, self._api_headers_base(token))

        async with await self._get_session().request(**req_params.__dict__) as response:
            response.raise_for_status()
            data: UserMetadataResponse = await response.json()
            return data

    async def get_appliances_list(
        self, base_url: str, token: str, include_metadata: bool
    ):
        req_params = list_appliances_url(
            base_url, self._api_headers_base(token), include_metadata
        )

        async with await self._get_session().request(**req_params.__dict__) as response:
            response.raise_for_status()
            data: list[ApplienceStatusResponse] = await response.json()
            return data

    async def get_appliance_state(
        self, base_url: str, token: str, id: str, include_metadata: bool
    ):
        req_params = get_appliance_by_id_url(
            base_url,
            self._api_headers_base(token),
            id,
            include_metadata,
        )

        async with await self._get_session().request(**req_params.__dict__) as response:
            response.raise_for_status()
            data: ApplienceStatusResponse = await response.json()
            return data

    async def get_appliance_capabilities(self, base_url: str, token: str, id: str):
        req_params = get_appliance_capabilities_url(
            base_url, self._api_headers_base(token), id
        )

        async with await self._get_session().request(**req_params.__dict__) as response:
            response.raise_for_status()
            data: Dict[str, Any] = await response.json()
            return data

    async def get_appliances_info(self, base_url: str, token: str, ids: list[str]):
        req_params = get_appliances_info_by_ids_url(
            base_url,
            self._api_headers_base(token),
            ids,
        )

        async with await self._get_session().request(**req_params.__dict__) as response:
            response.raise_for_status()
            data: list[ApplianceInfoResponse] = await response.json()
            return data

    async def execute_appliance_command(
        self, base_url: str, token: str, id: str, command_data: Dict[str, Any]
    ):
        req_params = appliance_command_url(
            base_url,
            self._api_headers_base(token),
            id,
            command_data,
        )

        async with await self._get_session().request(**req_params.__dict__) as response:
            response.raise_for_status()
            await response.wait_for_close()
            return

    async def close(self) -> None:
        if self._client_session and self._close_session:
            await self._client_session.close()

    async def __aenter__(self):
        return self

    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> Optional[bool]:
        await self.close()
