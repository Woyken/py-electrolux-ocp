import asyncio
from types import TracebackType
from typing import Any, Callable, Optional, Type
from aiohttp import ClientError, ClientSession, ClientWebSocketResponse, WSMsgType

from pyelectroluxconnect.Session import RequestError

from .apiModels import WebSocketResponse

class WebSocketClient:
    def __init__(self, url: str, clientSession: Optional[ClientSession] = None):
        self._client_session = clientSession
        self._close_session = False
        self._url = url
        self.websocket = None
        self.retry = False
        self.retry_interval = 5  # seconds
        self.heartbeat_interval = 5 * 60  # 5 minutes
        self.event_loop = asyncio.get_event_loop()
        self.event_handlers: list[Callable[[WebSocketResponse], None]] = []

    def _get_session(self):
        if self._client_session is None:
            self._client_session = ClientSession()
            self._close_session = True
        return self._client_session

    def add_event_handler(self, handler: Callable[[WebSocketResponse], None]):
        self.event_handlers.append(handler)

    def remove_event_handler(self, handler: Callable[[WebSocketResponse], None]):
        self.event_handlers.remove(handler)

    async def connect(self, headers: dict[str, Any]):
        await self.disconnect()
        await self._connect(headers)

    async def _connect(
        self, headers: dict[str, Any]
    ):
        self.retry = True
        while self.retry:
            try:
                async with self._get_session().ws_connect(
                    self._url,
                    headers=headers,
                    # Connection will be broken after 10 minutes of inactivity, keep it alive with heartbeat messages
                    heartbeat=self.heartbeat_interval,
                ) as ws:
                    self.websocket = ws
                    print("WebSocket connection established")
                    # Block until connection closes
                    await self.handle_messages(ws)
            except ClientError:
                print(
                    "WebSocket connection failed. Retrying in {} seconds.".format(
                        self.retry_interval
                    )
                )
                await asyncio.sleep(self.retry_interval)

    async def handle_messages(self, ws: ClientWebSocketResponse):
        try:
            async for msg in ws:
                print("websocket message received, type", str(msg.type))
                if isinstance(msg.data, str):
                    print("string message received", msg.data)

                if msg.type in (WSMsgType.CLOSE, WSMsgType.CLOSED, WSMsgType.CLOSING):
                    break
                if msg.type == WSMsgType.ERROR:
                    raise RequestError()

                if msg.type == WSMsgType.TEXT:
                    parsed_message: WebSocketResponse = msg.json()
                    # print(parsed_message["Payload"]["Appliances"][0]["Metrics"][0]["Name"])
                    for handler in self.event_handlers:
                        self.event_loop.call_soon(handler, parsed_message)
        finally:
            await ws.close()
            print("WebSocket connection closed")

    async def disconnect(self):
        self.retry = False
        if self.websocket is not None:
            await self.websocket.close()

    async def close(self) -> None:
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
