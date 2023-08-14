from base64 import b64decode
from datetime import datetime, timedelta
from json import loads
from typing import Any, Dict, Optional
from aiohttp import ClientSession

from .urls import (
    appliance_command,
    current_user_metadata_url,
    get_appliance_by_id,
    get_appliance_capabilities,
    get_appliances_info_by_ids,
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
        self.expiresAt = datetime.now() + timedelta(seconds=token["expiresIn"])

    def should_renew(self):
        return self.expiresAt < (datetime.now() - timedelta(minutes=2))


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

    async def login_client_credentials(self, baseUrl: str):
        """Login using client credentials of the mobile application, used for fetching identity providers urls"""
        reqParams = token_url(
            baseUrl,
            self._api_headers_base(None),
            "client_credentials",
            clientSecret=CLIENT_SECRET_ELECTROLUX,
        )

        async with await self._get_session().request(**reqParams.__dict__) as response:
            token: ClientCredTokenResponse = await response.json()
            return ClientToken(token)

    async def exchange_login_user(self, baseUrl: str, idToken: str):
        """Exchange external id token to api token"""
        decodedToken = decodeJwt(idToken)
        reqParams = token_url(
            baseUrl,
            {
                **self._api_headers_base(None),
                "Origin-Country-Code": decodedToken["country"],
            },
            "urn:ietf:params:oauth:grant-type:token-exchange",
            idToken=idToken,
        )

        async with await self._get_session().request(**reqParams.__dict__) as response:
            token: UserTokenResponse = await response.json()
            return UserToken(token)

    async def refresh_token_user(self, baseUrl: str, refreshToken: str):
        reqParams = token_url(
            baseUrl,
            self._api_headers_base(None),
            "refresh_token",
            refreshToken=refreshToken,
        )

        async with await self._get_session().request(**reqParams.__dict__) as response:
            newToken: UserTokenResponse = await response.json()
            return UserToken(newToken)

    async def get_identity_providers(
        self, baseUrl: str, clientCredToken: str, username: str
    ):
        reqParams = identity_providers_url(
            baseUrl,
            {
                **self._api_headers_base(None),
                "Authorization": clientCredToken,
            },
            BRAND_ELECTROLUX,
            username,
        )

        async with await self._get_session().request(**reqParams.__dict__) as response:
            data: list[AuthResponse] = await response.json()
            return data

    async def get_user_metadata(self, baseUrl: str, token: str):
        reqParams = current_user_metadata_url(baseUrl, self._api_headers_base(token))

        async with await self._get_session().request(**reqParams.__dict__) as response:
            data: UserMetadataResponse = await response.json()
            return data

    async def get_appliances_list(
        self, baseUrl: str, token: str, includeMetadata: bool
    ):
        reqParams = list_appliances_url(
            baseUrl, self._api_headers_base(token), includeMetadata
        )

        async with await self._get_session().request(**reqParams.__dict__) as response:
            data: list[ApplienceStatusResponse] = await response.json()
            return data

    async def get_appliance_status(self, baseUrl: str, token: str, id, includeMetadata):
        reqParams = get_appliance_by_id(
            baseUrl,
            self._api_headers_base(token),
            id,
            includeMetadata,
        )

        async with await self._get_session().request(**reqParams.__dict__) as response:
            data: ApplienceStatusResponse = await response.json()
            return data

    async def get_appliance_capabilities(self, baseUrl: str, token: str, id: str):
        reqParams = get_appliance_capabilities(
            baseUrl, self._api_headers_base(token), id
        )

        async with await self._get_session().request(**reqParams.__dict__) as response:
            data: Dict[str, Any] = await response.json()
            return data

    async def get_appliances_info(self, baseUrl: str, token: str, ids: list[str]):
        reqParams = get_appliances_info_by_ids(
            baseUrl,
            self._api_headers_base(token),
            ids,
        )

        async with await self._get_session().request(**reqParams.__dict__) as response:
            data: list[ApplianceInfoResponse] = await response.json()
            return data

    async def execute_appliance_command(
        self, baseUrl: str, token: str, id: str, commandData: Dict[str, Any]
    ):
        reqParams = appliance_command(
            baseUrl,
            self._api_headers_base(token),
            id,
            commandData,
        )

        async with await self._get_session().request(**reqParams.__dict__) as response:
            await response.wait_for_close()
            return
