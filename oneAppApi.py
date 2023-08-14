import asyncio
from datetime import datetime
from json import dumps
from types import TracebackType
from typing import Any, Callable, Dict, Optional, Type
from aiohttp import ClientSession

from .apiClient import ClientToken, OneAppApiClient, UserToken

from .const import (
    API_KEY_ELECTROLUX,
    BASE_URL,
    BASE_WEBSOCKET_URL,
)
from .webSocketClient import WebSocketClient
from .gigyaClient import GigyaClient
from .apiModels import (
    AuthResponse,
    UserTokenResponse,
    WebSocketResponse,
)


class OneAppApi:
    _regional_websocket_base_url: Optional[str] = None
    _gigya_client: Optional[GigyaClient] = None
    _ws_client: Optional[WebSocketClient] = None
    _client_cred_token: Optional[ClientToken] = None
    _user_token: Optional[UserToken] = None
    _identity_providers: Optional[list[AuthResponse]] = None
    _shutdown_complete_event: Optional[asyncio.Event] = None

    def __init__(
        self,
        username: str,
        password: str,
        client_session: Optional[ClientSession] = None,
    ) -> None:
        self._username = username
        self._password = password
        self._client_session = client_session
        self._close_session = False
        self._api_client = OneAppApiClient(client_session)
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

    async def _get_client_cred_token(self):
        """Login using client credentials of the mobile application, used for fetching identity providers urls"""
        if (
            self._client_cred_token is not None
            and not self._client_cred_token.should_renew()
        ):
            return self._client_cred_token

        baseUrl = await self._get_base_url()
        token = await self._api_client.login_client_credentials(baseUrl)
        self._client_cred_token = token
        return token

    async def get_formatted_client_cred_token(self):
        clientCredToken = await self._get_client_cred_token()
        return f'{clientCredToken.token["tokenType"]} {clientCredToken.token["accessToken"]}'

    async def _get_identity_providers(self):
        if self._identity_providers is not None:
            return self._identity_providers

        baseUrl = await self._get_base_url()
        token = await self.get_formatted_client_cred_token()

        providers = await self._api_client.get_identity_providers(
            baseUrl, token, self._username
        )
        self._identity_providers = providers
        return providers

    async def _get_base_url(self) -> str:
        if self._client_cred_token is None:
            return BASE_URL
        if self._identity_providers is None:
            return BASE_URL
        providers = await self._get_identity_providers()
        return providers[0]["httpRegionalBaseUrl"]

    async def _get_regional_websocket_base_url(self):
        if self._client_cred_token is None:
            return BASE_WEBSOCKET_URL
        providers = await self._get_identity_providers()
        return providers[0]["webSocketRegionalBaseUrl"]

    async def _get_gigya_client(self):
        if self._gigya_client is not None:
            return self._gigya_client
        data = await self._get_identity_providers()
        gigyaClient = GigyaClient(
            self._get_session(), data[0]["domain"], data[0]["apiKey"]
        )
        self._gigya_client = gigyaClient
        return gigyaClient

    async def _get_websocket_client(self):
        if self._ws_client is not None:
            return self._ws_client

        url = await self._get_regional_websocket_base_url()
        ws_client = WebSocketClient(self._get_session(), url)
        self._ws_client = ws_client
        return ws_client

    async def connect_websocket(self, appliances: list[str]):
        """Start websocket connection, listen to events"""
        token = await self.get_user_token()
        headers = self._api_headers_base(token.token)
        headers["appliances"] = dumps(
            [{"applianceId": applianceId} for applianceId in appliances]
        )
        headers["version"] = "2"
        ws_client = await self._get_websocket_client()

        await ws_client.connect(headers)

    async def disconnect_websocket(self):
        """Stop websocket connection"""
        ws_client = await self._get_websocket_client()
        await ws_client.disconnect()

    async def add_event_handler(self, handler: Callable[[WebSocketResponse], None]):
        """Add handler function for websocket events"""
        ws_client = await self._get_websocket_client()
        ws_client.add_event_handler(handler)

    async def remove_event_handler(self, handler: Callable[[WebSocketResponse], None]):
        """Remove handler function for websocket events"""
        ws_client = await self._get_websocket_client()
        ws_client.remove_event_handler(handler)

    async def get_user_token(self):
        if self._user_token is not None:
            if not self._user_token.should_renew():
                return self._user_token

            baseUrl = await self._get_base_url()

            token = await self._api_client.refresh_token_user(
                baseUrl, self._user_token.token["refreshToken"]
            )
            self._user_token = token
            return token

        gigyaClient = await self._get_gigya_client()
        idToken = await gigyaClient.login_user(self._username, self._password)
        baseUrl = await self._get_base_url()
        token = await self._api_client.exchange_login_user(baseUrl, idToken["id_token"])
        self._user_token = token
        return token

    async def get_formatted_user_token(self):
        token = await self.get_user_token()
        return f'{token.token["tokenType"]} {token.token["accessToken"]}'

    async def get_user_metadata(self):
        token = await self.get_formatted_user_token()
        baseUrl = await self._get_base_url()

        result = await self._api_client.get_user_metadata(baseUrl, token)
        return result

    async def get_appliances_list(self, includeMetadata: bool):
        token = await self.get_formatted_user_token()
        baseUrl = await self._get_base_url()

        result = await self._api_client.get_appliances_list(
            baseUrl, token, includeMetadata
        )
        return result

    async def get_appliance_status(self, id: str, includeMetadata: bool):
        token = await self.get_formatted_user_token()
        baseUrl = await self._get_base_url()

        result = await self._api_client.get_appliance_status(
            baseUrl, token, id, includeMetadata
        )
        return result

    async def get_appliance_capabilities(self, id: str):
        token = await self.get_formatted_user_token()
        baseUrl = await self._get_base_url()

        result = await self._api_client.get_appliance_capabilities(baseUrl, token, id)
        return result

    async def get_appliances_info(self, ids: list[str]):
        token = await self.get_formatted_user_token()
        baseUrl = await self._get_base_url()

        result = await self._api_client.get_appliances_info(baseUrl, token, ids)
        return result

    async def execute_appliance_command(self, id: str, commandData: Dict[str, Any]):
        token = await self.get_formatted_user_token()
        baseUrl = await self._get_base_url()
        result = await self._api_client.execute_appliance_command(
            baseUrl, token, id, commandData
        )
        return result

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
