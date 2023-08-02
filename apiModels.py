from typing import Any, Dict, Optional, TypedDict


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


class UserMetadataResponsePhoneNumber(TypedDict):
    type: str
    number: Optional[str]


class UserMetadataResponseMeasurementUnits(TypedDict):
    distanceMeasurementUnit: str
    tempMeasurementUnit: str
    surfaceMeasurementUnit: str
    weightMeasurementUnit: str
    volumeMeasurementUnit: str


class UserMetadataResponse(TypedDict):
    firstName: str
    lastName: str
    countryCode: str
    locale: str
    phoneNumbers: list[UserMetadataResponsePhoneNumber]
    enabledMarketingChannels: list[None]
    measurementUnits: UserMetadataResponseMeasurementUnits


class ApplienceStatusResponseApplianceData(TypedDict):
    applianceName: str
    created: str
    modelName: str


class ApplienceStatusResponseProperties(TypedDict):
    desired: Dict[str, Any]
    reported: Dict[str, Any]
    metadata: Dict[str, Any]


class ApplienceStatusResponse(TypedDict):
    applianceId: str
    status: str
    connectionState: str
    applianceData: ApplienceStatusResponseApplianceData
    properties: ApplienceStatusResponseProperties


class ApplianceInfoResponse(TypedDict):
    pnc: str
    brand: str
    market: str
    productArea: str
    deviceType: str
    project: str
    model: str
    variant: str
    colour: str
