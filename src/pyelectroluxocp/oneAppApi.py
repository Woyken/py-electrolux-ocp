import asyncio
from json import dump, dumps
from types import TracebackType
from typing import Any, Callable, Dict, Optional, Type
from aiohttp import ClientSession

from .oneAppApiClient import ClientToken, OneAppApiClient, UserToken
from .const import BASE_URL, BASE_WEBSOCKET_URL
from .webSocketClient import WebSocketClient
from .gigyaClient import GigyaClient
from .apiModels import AuthResponse, WebSocketResponse
import logging

_LOGGER: logging.Logger = logging.getLogger(__package__).getChild("OneAppApi")


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

    async def get_client_cred_token(self):
        """Login using client credentials of the mobile application, used for fetching identity providers urls"""
        if (
            self._client_cred_token is not None
            and not self._client_cred_token.should_renew()
        ):
            _LOGGER.debug("get_client_cred_token(), still valid token")
            return self._client_cred_token

        _LOGGER.debug("get_client_cred_token(), need to refresh token")
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
        _LOGGER.debug("connect_websocket(), headers: %s", dumps(headers))
        task = asyncio.create_task(ws_client.connect(headers))
        self._running_tasks.add(task)
        task.add_done_callback(self._running_tasks.discard)

        return await task

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
                _LOGGER.debug(
                    "get_user_token(), return existing token, expiresAt: %s",
                    self._user_token.expiresAt,
                )
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
        _LOGGER.debug("get_user_metadata()")
        token = await self._get_formatted_user_token()
        base_url = await self._get_base_url()

        result = await self._api_client.get_user_metadata(base_url, token)
        return result

    async def get_appliances_list(self, include_metadata: bool = False):
        """Get list of all user's appliances"""
        _LOGGER.debug("get_appliances_list(), include_metadata: %s", include_metadata)
        token = await self._get_formatted_user_token()
        base_url = await self._get_base_url()

        result = await self._api_client.get_appliances_list(
            base_url, token, include_metadata
        )
        return result

    async def get_appliance_state(self, id: str, include_metadata: bool = False):
        """Get current state of appliance by id"""
        _LOGGER.debug(
            "get_appliance_state(), id: %s, include_metadata: %s",
            id,
            include_metadata,
        )
        token = await self._get_formatted_user_token()
        base_url = await self._get_base_url()

        result = await self._api_client.get_appliance_state(
            base_url, token, id, include_metadata
        )
        return result

    async def get_appliance_capabilities(self, id: str):
        """Get appliance capabilities"""
        _LOGGER.debug("get_appliance_capabilities(), id: %s", id)
        token = await self._get_formatted_user_token()
        base_url = await self._get_base_url()

        result = await self._api_client.get_appliance_capabilities(base_url, token, id)
        return result

    async def get_appliances_info(self, ids: list[str]):
        """Get multiple appliances info"""
        _LOGGER.debug("get_appliances_info(), ids: %s", dumps(ids))
        token = await self._get_formatted_user_token()
        baseUrl = await self._get_base_url()

        result = await self._api_client.get_appliances_info(baseUrl, token, ids)
        return result

    async def execute_appliance_command(self, id: str, command_data: Dict[str, Any]):
        """Execute command for appliance"""
        _LOGGER.debug(
            "execute_appliance_command(), id: %s, command_data: %s",
            id,
            dumps(command_data),
        )
        token = await self._get_formatted_user_token()
        base_url = await self._get_base_url()
        result = await self._api_client.execute_appliance_command(
            base_url, token, id, command_data
        )
        return result

    async def watch_for_appliance_state_updates(
        self,
        appliance_ids: list[str],
        callback: Callable[[dict[str, Dict[str, Any]]], None],
    ):
        """Fetch current appliance state and watch for state changes"""

        def handle_websocket_response(responseData: WebSocketResponse):
            _LOGGER.debug(
                "watch_for_appliance_state_updates().handle_websocket_response, responseData: %s",
                dumps(responseData),
            )
            for appliance_update_data in responseData.get("Payload").get("Appliances"):
                appliance_id = appliance_update_data.get("ApplianceId")
                if appliance_id in appliance_ids:
                    appliance_state_update_dict: dict[str, Dict[str, Any]] = {
                        appliance_id: {}
                    }
                    for appliance_metric in appliance_update_data.get("Metrics"):
                        appliance_state_update_dict[appliance_id][
                            appliance_metric.get("Name")
                        ] = appliance_metric.get("Value")
                    callback(appliance_state_update_dict)

        def handle_disconnected_or_connected_event():
            _LOGGER.debug(
                "watch_for_appliance_state_updates().handle_disconnected_or_connected_event"
            )

            async def async_impl():
                appliances_states = await self.get_appliances_list(False)
                for applianceState in appliances_states:
                    if applianceState.get("applianceId") in appliance_ids:
                        appliance_state_update_dict = {
                            applianceState.get("applianceId"): applianceState.get(
                                "properties"
                            ).get("reported")
                        }
                        callback(appliance_state_update_dict)

            task = asyncio.create_task(async_impl())
            self._running_tasks.add(task)
            task.add_done_callback(self._running_tasks.discard)

        await self.add_event_handler(handle_websocket_response)
        ws_client = await self._get_websocket_client()
        # On every websocket reconnection fetch whole state again once more
        ws_client.add_connected_event_handler(handle_disconnected_or_connected_event)
        # TODO add interval polling while disconnected from websocket
        ws_client.add_disconnected_event_handler(handle_disconnected_or_connected_event)

        await self.connect_websocket(appliance_ids)

    async def debug_dump_everything_to_files(
        self, export_location: Optional[str] = None
    ):
        """DEBUG, Fetch everything and dump to temporary files. Default export location: ~/py-electrolux-ocp-dump/..."""
        from pathlib import Path

        home = Path.home() if export_location is None else Path(export_location)
        dump_path = home.joinpath("py-electrolux-ocp-dump")
        from shutil import rmtree

        rmtree(dump_path, ignore_errors=True)
        dump_path.mkdir(exist_ok=True)

        user_metadata = await self.get_user_metadata()
        with open(dump_path.joinpath("userMetadata.json"), "w", encoding="utf-8") as f:
            dump(user_metadata, f, ensure_ascii=False, indent=4)

        appliances_list = await self.get_appliances_list(True)
        with open(
            dump_path.joinpath("appliancesList.json"), "w", encoding="utf-8"
        ) as f:
            dump(appliances_list, f, ensure_ascii=False, indent=4)

        appliances_info = await self.get_appliances_info(
            [x["applianceId"] for x in appliances_list]
        )
        with open(
            dump_path.joinpath("appliancesInfo.json"), "w", encoding="utf-8"
        ) as f:
            dump(appliances_info, f, ensure_ascii=False, indent=4)

        for appliance in appliances_list:
            import base64

            appliance_id_folder_name = base64.urlsafe_b64encode(
                appliance["applianceId"].encode()
            ).decode()
            dump_path_appliance = dump_path.joinpath(appliance_id_folder_name)
            dump_path_appliance.mkdir(exist_ok=True)
            appliance_capabilities = await self.get_appliance_capabilities(
                appliance["applianceId"]
            )
            with open(
                dump_path_appliance.joinpath("applianceCapabilities.json"),
                "w",
                encoding="utf-8",
            ) as f:
                dump(appliance_capabilities, f, ensure_ascii=False, indent=4)

            appliance_state = await self.get_appliance_state(
                appliance["applianceId"], True
            )
            with open(
                dump_path_appliance.joinpath("applianceState.json"),
                "w",
                encoding="utf-8",
            ) as f:
                dump(appliance_state, f, ensure_ascii=False, indent=4)

        print("DUMP generated at", dump_path)

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
            _LOGGER.debug(
                "_get_base_url(), client_cred is not set, return BASE_URL: %s",
                BASE_URL,
            )
            return BASE_URL
        if self._identity_providers is None:
            _LOGGER.debug(
                "_get_base_url(), _identity_providers is not set, return BASE_URL: %s",
                BASE_URL,
            )
            return BASE_URL

        providers = await self._get_identity_providers()
        _LOGGER.debug(
            "_get_base_url(), getting identity providers, return first result.httpRegionalBaseUrl: %s",
            providers[0]["httpRegionalBaseUrl"],
        )
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
