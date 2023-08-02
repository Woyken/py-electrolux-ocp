import asyncio
from base64 import b64decode
from datetime import datetime, timedelta
from json import loads, dumps
from types import TracebackType
from typing import Any, Callable, Dict, Optional, Type
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
    BASE_URL,
    BASE_WEBSOCKET_URL,
    BRAND_ELECTROLUX,
    CLIENT_SECRET_ELECTROLUX,
)
from .webSocketClient import WebSocketClient
from .gigyaClient import GigyaClient
from .apiModels import (
    ApplianceInfoResponse,
    ApplienceStatusResponse,
    AuthResponse,
    ClientCredTokenResponse,
    UserMetadataResponse,
    UserTokenResponse,
    WebSocketResponse,
)


def decodeJwt(token: str):
    token_payload = token.split(".")[1]
    token_payload_decoded = str(b64decode(token_payload + "=="), "utf-8")
    payload: dict[str, Any] = loads(token_payload_decoded)
    return payload


class UserToken:
    def __init__(self, token: UserTokenResponse) -> None:
        self.token = token
        self.expiresAt = datetime.now() + timedelta(seconds=token["expiresIn"])


class ClientToken:
    def __init__(self, token: ClientCredTokenResponse) -> None:
        self.token = token
        self.expiresAt = datetime.now() + timedelta(seconds=token["expiresIn"])


class OneAppApi:
    _regional_websocket_base_url: Optional[str] = None
    _gigya_client: Optional[GigyaClient] = None
    _ws_client: Optional[WebSocketClient] = None
    _client_cred_token: Optional[ClientToken] = None
    _user_token: Optional[UserToken] = None
    _identity_providers: Optional[list[AuthResponse]] = None
    _shutdown_complete_event: Optional[asyncio.Event] = None

    def __init__(self, client_session: Optional[ClientSession] = None) -> None:
        self._client_session = client_session
        self._close_session = False
        pass

    def _get_session(self):
        if self._client_session is None:
            self._client_session = ClientSession()
            self._close_session = True
        return self._client_session

    def _api_headers_base(self, userToken: Optional[UserTokenResponse] = None):
        headers = {"x-api-key": API_KEY_ELECTROLUX}
        if userToken is not None:
            headers = {
                **headers,
                "Authorization": f'{userToken["tokenType"]} {userToken["accessToken"]}',
            }
        return headers

    async def _fetch_login_client_credentials(self, username: str):
        """Login using client credentials of the mobile application, used for fetching identity providers urls"""
        reqParams = token_url(
            await self._get_base_url(username),
            self._api_headers_base(),
            "client_credentials",
            clientSecret=CLIENT_SECRET_ELECTROLUX,
        )

        async with await self._get_session().request(**reqParams.__dict__) as response:
            token: ClientCredTokenResponse = await response.json()
            return ClientToken(token)

    async def _get_client_cred_token(self, username: str):
        if (
            self._client_cred_token is not None
            and self._client_cred_token.expiresAt > datetime.now()
        ):
            return self._client_cred_token
        token = await self._fetch_login_client_credentials(username)
        self._client_cred_token = token
        return token

    async def _fetch_exchange_login_user(self, username: str, idToken: str):
        decodedToken = decodeJwt(idToken)
        reqParams = token_url(
            await self._get_base_url(username),
            {
                **self._api_headers_base(),
                "Origin-Country-Code": decodedToken["country"],
            },
            "urn:ietf:params:oauth:grant-type:token-exchange",
            idToken=idToken,
        )

        async with await self._get_session().request(**reqParams.__dict__) as response:
            token: UserTokenResponse = await response.json()
            return UserToken(token)

    async def _fetch_refresh_token_user(self, username: str, token: UserToken):
        reqParams = token_url(
            await self._get_base_url(username),
            self._api_headers_base(),
            "refresh_token",
            refreshToken=token.token["refreshToken"],
        )

        async with await self._get_session().request(**reqParams.__dict__) as response:
            newToken: UserTokenResponse = await response.json()
            return UserToken(newToken)

    async def _fetch_identity_providers(
        self, username: str, clientCredToken: ClientCredTokenResponse
    ):
        reqParams = identity_providers_url(
            await self._get_base_url(username),
            {
                **self._api_headers_base(),
                "Authorization": f'{clientCredToken["tokenType"]} {clientCredToken["accessToken"]}',
            },
            BRAND_ELECTROLUX,
            username,
        )

        async with await self._get_session().request(**reqParams.__dict__) as response:
            data: list[AuthResponse] = await response.json()
            return data

    async def _get_identity_providers(self, username: str):
        if self._identity_providers is not None:
            return self._identity_providers
        token = await self._get_client_cred_token(username)
        providers = await self._fetch_identity_providers(username, token.token)
        self._identity_providers = providers
        return providers

    async def _get_base_url(self, username: str) -> str:
        if self._client_cred_token is None:
            return BASE_URL
        if self._identity_providers is None:
            return BASE_URL
        providers = await self._get_identity_providers(username)
        return providers[0]["httpRegionalBaseUrl"]

    async def _get_regional_websocket_base_url(self, username: str):
        if self._client_cred_token is None:
            return BASE_WEBSOCKET_URL
        providers = await self._get_identity_providers(username)
        return providers[0]["webSocketRegionalBaseUrl"]

    async def _get_gigya_client(self, username: str):
        if self._gigya_client is not None:
            return self._gigya_client
        data = await self._get_identity_providers(username)
        gigyaClient = GigyaClient(
            self._get_session(), data[0]["domain"], data[0]["apiKey"]
        )
        self._gigya_client = gigyaClient
        return gigyaClient

    async def _get_websocket_client(self, username: str):
        if self._ws_client is not None:
            return self._ws_client

        session = self._get_session()
        url = await self._get_regional_websocket_base_url(username)
        ws_client = WebSocketClient(session, url)
        self._ws_client = ws_client
        return ws_client

    async def connect_websocket(
        self, username: str, password: str, appliances: list[str]
    ):
        """Start websocket connection, listen to events"""
        token = await self.get_user_token(username, password)
        headers = self._api_headers_base(token.token)
        headers["appliances"] = dumps(
            [{"applianceId": applianceId} for applianceId in appliances]
        )
        headers["version"] = "2"
        ws_client = await self._get_websocket_client(username)

        await ws_client.connect(headers)

    async def disconnect_websocket(self, username: str):
        """Stop websocket connection"""
        ws_client = await self._get_websocket_client(username)
        await ws_client.disconnect()

    async def add_event_handler(
        self, username: str, handler: Callable[[WebSocketResponse], None]
    ):
        """Add handler function for websocket events"""
        ws_client = await self._get_websocket_client(username)
        ws_client.add_event_handler(handler)

    async def remove_event_handler(
        self, username: str, handler: Callable[[WebSocketResponse], None]
    ):
        """Remove handler function for websocket events"""
        ws_client = await self._get_websocket_client(username)
        ws_client.remove_event_handler(handler)

    async def get_user_token(self, username: str, password: str):
        if self._user_token is not None:
            if self._user_token.expiresAt > datetime.now():
                return self._user_token
            token = await self._fetch_refresh_token_user(username, self._user_token)
            self._user_token = token
            return token

        gigyaClient = await self._get_gigya_client(username)
        idToken = await gigyaClient.login_user(username, password)
        token = await self._fetch_exchange_login_user(username, idToken["id_token"])
        self._user_token = token
        return token

    async def get_user_metadata(self, username: str, password: str):
        token = await self.get_user_token(username, password)
        reqParams = current_user_metadata_url(
            await self._get_base_url(username),
            self._api_headers_base(token.token),
        )

        async with await self._get_session().request(**reqParams.__dict__) as response:
            data: UserMetadataResponse = await response.json()
            return data

    async def get_appliances_list(
        self, username: str, password: str, includeMetadata: bool
    ):
        token = await self.get_user_token(username, password)
        reqParams = list_appliances_url(
            await self._get_base_url(username),
            self._api_headers_base(token.token),
            includeMetadata,
        )

        async with await self._get_session().request(**reqParams.__dict__) as response:
            data: list[ApplienceStatusResponse] = await response.json()
            return data

    async def get_appliance_status(
        self, username: str, password: str, id: str, includeMetadata: bool
    ):
        token = await self.get_user_token(username, password)
        reqParams = get_appliance_by_id(
            await self._get_base_url(username),
            self._api_headers_base(token.token),
            id,
            includeMetadata,
        )

        async with await self._get_session().request(**reqParams.__dict__) as response:
            data: ApplienceStatusResponse = await response.json()
            return data

    async def get_appliance_capabilities(self, username: str, password: str, id: str):
        token = await self.get_user_token(username, password)
        reqParams = get_appliance_capabilities(
            await self._get_base_url(username),
            self._api_headers_base(token.token),
            id,
        )

        async with await self._get_session().request(**reqParams.__dict__) as response:
            data: Dict[str, Any] = await response.json()
            return data

    async def get_appliances_info(self, username: str, password: str, ids: list[str]):
        token = await self.get_user_token(username, password)
        reqParams = get_appliances_info_by_ids(
            await self._get_base_url(username),
            self._api_headers_base(token.token),
            ids,
        )

        async with await self._get_session().request(**reqParams.__dict__) as response:
            data: list[ApplianceInfoResponse] = await response.json()
            return data

    async def execute_appliance_command(
        self, username: str, password: str, id: str, commandData: Dict[str, Any]
    ):
        token = await self.get_user_token(username, password)
        reqParams = appliance_command(
            await self._get_base_url(username),
            self._api_headers_base(token.token),
            id,
            commandData,
        )

        async with await self._get_session().request(**reqParams.__dict__) as response:
            await response.wait_for_close()
            return

    async def close(self) -> None:
        if self._client_session and self._close_session:
            await self._client_session.close()
        if self._gigya_client:
            await self._gigya_client.close()
        if self._ws_client:
            await self._ws_client.close()

    async def __aenter__(self):
        return self

    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> Optional[bool]:
        await self.close()
