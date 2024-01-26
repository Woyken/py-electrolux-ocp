import asyncio
from json import dumps
from types import TracebackType
from typing import Any, Callable, Dict, Optional, Type
from aiohttp import ClientSession

from .apiClient import ClientToken, OneAppApiClient, UserToken
from .const import BASE_URL, BASE_WEBSOCKET_URL
from .webSocketClient import WebSocketClient
from .gigyaClient import GigyaClient
from .apiModels import AuthResponse, WebSocketResponse


class OneAppApi:
    _regional_websocket_base_url: Optional[str] = None
    _gigya_client: Optional[GigyaClient] = None
    _ws_client: Optional[WebSocketClient] = None
    _client_cred_token: Optional[ClientToken] = None
    _user_token: Optional[UserToken] = None
    _identity_providers: Optional[list[AuthResponse]] = None
    _shutdown_complete_event: Optional[asyncio.Event] = None
    _running_tasks: set[asyncio.Task] = set()

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

    async def get_client_cred_token(self):
        """Login using client credentials of the mobile application, used for fetching identity providers urls"""
        if (
            self._client_cred_token is not None
            and not self._client_cred_token.should_renew()
        ):
            return self._client_cred_token

        base_url = await self._get_base_url()
        token = await self._api_client.login_client_credentials(base_url)
        self._client_cred_token = token
        return token

    async def connect_websocket(self, appliance_ids: list[str]):
        """Start websocket connection, listen to events"""
        token = await self._get_formatted_user_token()
        headers = {
            "Authorization": token,
            "appliances": dumps(
                [{"applianceId": appliance_id} for appliance_id in appliance_ids]
            ),
            "version": "2",
        }
        ws_client = await self._get_websocket_client()

        # Connect to websocket and don't wait
        task = asyncio.create_task(ws_client.connect(headers))
        self._running_tasks.add(task)
        task.add_done_callback(self._running_tasks.discard)

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
        """
        Login with user credentials.
        If already logged in and token expired, login using refresh token.
        """
        if self._user_token is not None:
            if not self._user_token.should_renew():
                return self._user_token

            base_url = await self._get_base_url()

            token = await self._api_client.refresh_token_user(
                base_url, self._user_token.token["refreshToken"]
            )
            self._user_token = token
            return token

        gigya_client = await self._get_gigya_client()
        id_token = await gigya_client.login_user(self._username, self._password)
        base_url = await self._get_base_url()
        token = await self._api_client.exchange_login_user(
            base_url, id_token["id_token"]
        )
        self._user_token = token
        return token

    async def get_user_metadata(self):
        """Get details about user and preferences"""
        token = await self._get_formatted_user_token()
        base_url = await self._get_base_url()

        result = await self._api_client.get_user_metadata(base_url, token)
        return result

    async def get_appliances_list(self, include_metadata: bool = False):
        """Get list of all user's appliances"""
        token = await self._get_formatted_user_token()
        base_url = await self._get_base_url()

        result = await self._api_client.get_appliances_list(
            base_url, token, include_metadata
        )
        return result

    async def get_appliance_status(self, id: str, include_metadata: bool = False):
        """Get current status of appliance by id"""
        token = await self._get_formatted_user_token()
        base_url = await self._get_base_url()

        result = await self._api_client.get_appliance_status(
            base_url, token, id, include_metadata
        )
        return result

    async def get_appliance_capabilities(self, id: str):
        """Get appliance capabilities"""
        token = await self._get_formatted_user_token()
        base_url = await self._get_base_url()

        result = await self._api_client.get_appliance_capabilities(base_url, token, id)
        return result

    async def get_appliances_info(self, ids: list[str]):
        """Get multiple appliances info"""
        token = await self._get_formatted_user_token()
        baseUrl = await self._get_base_url()

        result = await self._api_client.get_appliances_info(baseUrl, token, ids)
        return result

    async def execute_appliance_command(self, id: str, command_data: Dict[str, Any]):
        """Execute command for appliance"""
        token = await self._get_formatted_user_token()
        base_url = await self._get_base_url()
        result = await self._api_client.execute_appliance_command(
            base_url, token, id, command_data
        )
        return result

    async def watch_for_appliance_state_updates(
        self, appliance_ids: list[str], callback: Callable[[Dict[str, Any]], None]
    ):
        """Fetch current appliance state and watch for state changes"""

        def handle_websocket_response(responseData: WebSocketResponse):
            for appliance_update_data in responseData.get("Payload").get("Appliances"):
                if appliance_update_data.get("ApplianceId") in appliance_ids:
                    appliance_state_update_dict: Dict[str, Any] = dict()
                    for appliance_metric in appliance_update_data.get("Metrics"):
                        appliance_state_update_dict[
                            appliance_metric.get("Name")
                        ] = appliance_metric.get("Value")
                    callback(appliance_state_update_dict)

        def handle_disconnected_or_connected_event():
            async def async_impl():
                appliances_states = await self.get_appliances_list(False)
                for applianceState in appliances_states:
                    if applianceState.get("applianceId") in appliance_ids:
                        callback(applianceState.get("properties").get("reported"))

            asyncio.get_event_loop().call_soon(async_impl)

        await self.add_event_handler(handle_websocket_response)
        ws_client = await self._get_websocket_client()
        # On every websocket reconnection fetch whole state again once more
        ws_client.add_connected_event_handler(handle_disconnected_or_connected_event)
        # TODO add interval polling while disconnected from websocket
        ws_client.add_disconnected_event_handler(handle_disconnected_or_connected_event)

        await self.connect_websocket(appliance_ids)

    async def close(self) -> None:
        """Dispose session and dependencies"""
        if self._gigya_client:
            await self._gigya_client.close()
        if self._ws_client:
            await self._ws_client.close()

        await self._api_client.close()

        if self._client_session and self._close_session:
            await self._client_session.close()

        for task in self._running_tasks:
            task.cancel()

    async def _get_formatted_client_cred_token(self):
        client_cred_token = await self.get_client_cred_token()
        return f'{client_cred_token.token["tokenType"]} {client_cred_token.token["accessToken"]}'

    def _get_session(self):
        if self._client_session is None:
            self._client_session = ClientSession()
            self._close_session = True
        return self._client_session

    async def _get_identity_providers(self):
        if self._identity_providers is not None:
            return self._identity_providers

        baseUrl = await self._get_base_url()
        token = await self._get_formatted_client_cred_token()

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
        gigya_client = GigyaClient(
            data[0]["domain"], data[0]["apiKey"], self._get_session()
        )
        self._gigya_client = gigya_client
        return gigya_client

    async def _get_websocket_client(self):
        if self._ws_client is not None:
            return self._ws_client

        url = await self._get_regional_websocket_base_url()
        ws_client = WebSocketClient(url, self._get_session())
        self._ws_client = ws_client
        return ws_client

    async def _get_formatted_user_token(self):
        token = await self.get_user_token()
        return f'{token.token["tokenType"]} {token.token["accessToken"]}'

    async def __aenter__(self):
        return self

    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> Optional[bool]:
        await self.close()
