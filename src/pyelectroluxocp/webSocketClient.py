import asyncio
import logging
from types import TracebackType
from typing import Any, Callable, Coroutine, Optional, Type
from aiohttp import ClientError, ClientSession, ClientWebSocketResponse, WSMsgType

from .apiModels import WebSocketResponse


class WebSocketClient:
    def __init__(
        self,
        url: str,
        client_session: Optional[ClientSession] = None,
        logger: Optional[logging.Logger] = None,
    ):
        self._client_session = client_session
        self._close_session = False
        self._url = url
        self.websocket = None
        self.retry = False
        self.retry_interval = 5  # seconds
        self.heartbeat_interval = 5 * 60  # 5 minutes
        self.event_loop = asyncio.get_event_loop()
        self.event_handlers: set[Callable[[WebSocketResponse], None]] = set()
        self.event_websocket_connected_handlers: set[Callable[[], None]] = set()
        self.event_websocket_disconnected_handlers: set[Callable[[], None]] = set()
        package_root_logger = logger if logger else logging.getLogger(__package__)
        self._LOGGER = package_root_logger.getChild("WebSocketClient")

    def _get_session(self):
        if self._client_session is None:
            self._client_session = ClientSession()
            self._close_session = True
        return self._client_session

    def add_event_handler(self, handler: Callable[[WebSocketResponse], None]):
        self.event_handlers.add(handler)

    def remove_event_handler(self, handler: Callable[[WebSocketResponse], None]):
        self.event_handlers.discard(handler)

    def add_connected_event_handler(self, handler: Callable[[], None]):
        self.event_websocket_connected_handlers.add(handler)

    def remove_connected_event_handler(self, handler: Callable[[], None]):
        self.event_websocket_connected_handlers.discard(handler)

    def add_disconnected_event_handler(self, handler: Callable[[], None]):
        self.event_websocket_disconnected_handlers.add(handler)

    def remove_disconnected_event_handler(self, handler: Callable[[], None]):
        self.event_websocket_disconnected_handlers.discard(handler)

    async def connect(
        self, get_headers: Callable[[], Coroutine[Any, Any, dict[str, Any]]]
    ):
        self._LOGGER.debug("connect()")
        await self.disconnect()
        await self._connect(get_headers)

    async def _connect(
        self, get_headers: Callable[[], Coroutine[Any, Any, dict[str, Any]]]
    ):
        self._LOGGER.debug("_connect()")
        self.retry = True
        while self.retry:
            try:
                headers = await get_headers()
                self._LOGGER.debug("_connect(), while.connect(), retry: %s", self.retry)
                async with self._get_session().ws_connect(
                    self._url,
                    headers=headers,
                    # Connection will be broken after 10 minutes of inactivity, keep it alive with heartbeat messages
                    heartbeat=self.heartbeat_interval,
                ) as ws:
                    self.websocket = ws

                    for handler in self.event_websocket_connected_handlers:
                        self.event_loop.call_soon(handler)

                    # Block until connection closes
                    await self.handle_messages(ws)
            except ClientError as error:
                self._LOGGER.error("_connect(), ClientError: %s", error)
                # Connection dropped, retry in couple of seconds
                await asyncio.sleep(self.retry_interval)
            except Exception as error:
                self._LOGGER.error("_connect(), Exception: %s", error)
                # Unknown error
                await asyncio.sleep(self.retry_interval * 5)
        self._LOGGER.debug("_connect(), ENDED, retry: %s", self.retry)

    async def handle_messages(self, ws: ClientWebSocketResponse):
        try:
            async for msg in ws:
                self._LOGGER.debug("handle_messages(), msg: %s", msg)
                if msg.type in (WSMsgType.CLOSE, WSMsgType.CLOSED, WSMsgType.CLOSING):
                    break
                if msg.type == WSMsgType.ERROR:
                    raise Exception("Websocket error")

                if msg.type == WSMsgType.TEXT:
                    parsed_message: WebSocketResponse = msg.json()
                    self._LOGGER.debug(
                        "handle_messages(), msg.json(): %s", parsed_message
                    )
                    for handler in self.event_handlers:
                        self.event_loop.call_soon(handler, parsed_message)
            self._LOGGER.debug("handle_messages(), loop ENDED")
        finally:
            self._LOGGER.debug("handle_messages(), finally")
            await ws.close()
            # Inform listeners about socket close event
            for handler in self.event_websocket_disconnected_handlers:
                self.event_loop.call_soon(handler)

    async def disconnect(self):
        self._LOGGER.debug("disconnect()")
        self.retry = False
        if self.websocket is not None:
            await self.websocket.close()

    async def close(self) -> None:
        self._LOGGER.debug("close()")
        self.retry = False
        if self.websocket is not None:
            await self.websocket.close()
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
