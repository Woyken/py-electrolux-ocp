import asyncio
from base64 import b64decode
from datetime import datetime, timedelta
from json import loads, dumps
from types import TracebackType
from typing import Any, Optional, Type
from urllib.parse import urljoin
from aiohttp import ClientSession

from .const import (
    API_KEY_ELECTROLUX, 
    BASE_URL, 
    BASE_WEBSOCKET_URL, 
    CLIENT_ID_ELECTROLUX, 
    CLIENT_SECRET_ELECTROLUX
)
from .webSocketClient import WebSocketClient
from .gigyaClient import GigyaClient
from .apiModels import (
    AuthResponse,
    ClientCredTokenResponse,
    UserTokenResponse,
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
    _client_token: Optional[ClientToken] = None
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
            headers[
                "Authorization"
            ] = f'{userToken["tokenType"]} {userToken["accessToken"]}'
        return headers

    async def _fetch_login_client_credentials(self, username: str):
        # https://api.ocp.electrolux.one/one-account-authorization/api/v1/token
        url = urljoin(
            await self._get_regional_base_url(username),
            "one-account-authorization/api/v1/token",
        )
        async with await self._get_session().post(
            url,
            json={
                "grantType": "client_credentials",
                "clientId": CLIENT_ID_ELECTROLUX,
                "clientSecret": CLIENT_SECRET_ELECTROLUX,
                "scope": "",
            },
            headers=self._api_headers_base(),
        ) as response:
            token: ClientCredTokenResponse = await response.json()
            return ClientToken(token)

    async def _get_client_token(self, username: str):
        if (
            self._client_token is not None
            and self._client_token.expiresAt > datetime.now()
        ):
            return self._client_token
        token = await self._fetch_login_client_credentials(username)
        self._client_token = token
        return token

    async def _fetch_exchange_login_user(self, username: str, idToken: str):
        # https://api.ocp.electrolux.one/one-account-authorization/api/v1/token
        url = urljoin(
            await self._get_regional_base_url(username),
            "one-account-authorization/api/v1/token",
        )
        decodedToken = decodeJwt(idToken)
        headers = self._api_headers_base()
        headers["Origin-Country-Code"] = decodedToken["country"]
        async with await self._get_session().post(
            url,
            json={
                "grantType": "urn:ietf:params:oauth:grant-type:token-exchange",
                "clientId": CLIENT_ID_ELECTROLUX,
                "idToken": idToken,
                "scope": "",
            },
            headers=headers,
        ) as response:
            token: UserTokenResponse = await response.json()
            return UserToken(token)

    async def _fetch_refresh_token_user(self, username: str, token: UserToken):
        # https://api.ocp.electrolux.one/one-account-authorization/api/v1/token
        url = urljoin(
            await self._get_regional_base_url(username),
            "one-account-authorization/api/v1/token",
        )
        async with await self._get_session().post(
            url,
            json={
                "grantType": "refresh_token",
                "clientId": CLIENT_ID_ELECTROLUX,
                "refreshToken": token.token["refreshToken"],
                "scope": "",
            },
            headers=self._api_headers_base(),
        ) as response:
            newToken: UserTokenResponse = await response.json()
            return UserToken(newToken)

    async def _fetch_identity_providers(
        self, username: str, clientToken: ClientCredTokenResponse
    ):
        # https://api.ocp.electrolux.one/one-account-user/api/v1/identity-providers?brand=electrolux&email={{username}}
        url = urljoin(
            await self._get_regional_base_url(username),
            "one-account-user/api/v1/identity-providers",
        )
        headers = self._api_headers_base()
        headers[
            "Authorization"
        ] = f'{clientToken["tokenType"]} {clientToken["accessToken"]}'
        async with await self._get_session().get(
            url, params={"brand": "electrolux", "email": username}, headers=headers
        ) as response:
            data: list[AuthResponse] = await response.json()
            return data

    async def _get_identity_providers(self, username: str):
        if self._identity_providers is not None:
            return self._identity_providers
        token = await self._get_client_token(username)
        providers = await self._fetch_identity_providers(username, token.token)
        self._identity_providers = providers
        return providers

    async def _get_regional_base_url(self, username: str) -> str:
        if self._client_token is None:
            return BASE_URL
        if self._identity_providers is None:
            return BASE_URL
        providers = await self._get_identity_providers(username)
        return providers[0]["httpRegionalBaseUrl"]

    async def _get_regional_websocket_base_url(self, username: str):
        if self._client_token is None:
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
        token = await self.get_user_token(username, password)
        headers = self._api_headers_base(token.token)
        headers["appliances"] = dumps(
            [{"applianceId": applianceId} for applianceId in appliances]
        )
        headers["version"] = "2"
        ws_client = await self._get_websocket_client(username)

        await ws_client.connect(headers)

    async def disconnect_websocket(self, username: str):
        ws_client = await self._get_websocket_client(username)
        await ws_client.disconnect()

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
