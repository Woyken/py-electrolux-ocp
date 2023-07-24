from typing import Any, TypedDict


class UserTokenResponse(TypedDict):
    accessToken: str
    expiresIn: int
    tokenType: str
    refreshToken: str
    scope: str


class ClientCredTokenResponse(TypedDict):
    accessToken: str
    expiresIn: int
    tokenType: str
    scope: str


class AuthResponse(TypedDict):
    domain: str
    apiKey: str
    brand: str
    httpRegionalBaseUrl: str
    webSocketRegionalBaseUrl: str
    dataCenter: str


class WebSocketResponsePayloadApplianceMetric(TypedDict):
    Name: str
    Value: Any
    Timestamp: str


class WebSocketResponsePayloadAppliance(TypedDict):
    ApplianceId: str
    Metrics: list[WebSocketResponsePayloadApplianceMetric]


class WebSocketResponsePayload(TypedDict):
    Appliances: list[WebSocketResponsePayloadAppliance]


class WebSocketResponse(TypedDict):
    ConnectionId: str
    Api: str
    Version: str
    Payload: WebSocketResponsePayload
