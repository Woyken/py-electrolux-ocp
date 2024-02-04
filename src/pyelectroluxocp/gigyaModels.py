from typing import TypedDict


class SocializeGetIdsResponse(TypedDict):
    callId: str
    errorCode: int
    apiVersion: int
    statusCode: int
    statusReason: str
    time: str
    gmid: str
    gcid: str
    ucid: str


class LoginResponseProfile(TypedDict):
    firstName: str
    lastName: str
    country: str
    email: str


class LoginResponseSessionInfo(TypedDict):
    sessionToken: str
    sessionSecret: str
    expires_in: str


class LoginResponse(TypedDict):
    callId: str
    errorCode: int
    apiVersion: int
    statusCode: int
    statusReason: str
    time: str
    registeredTimestamp: int
    UID: str
    UIDSignature: str
    signatureTimestamp: str
    created: str
    createdTimestamp: int
    isActive: bool
    isRegistered: bool
    isVerified: bool
    lastLogin: str
    lastLoginTimestamp: int
    lastUpdated: str
    lastUpdatedTimestamp: int
    loginProvider: str
    oldestDataUpdated: str
    oldestDataUpdatedTimestamp: int
    profile: LoginResponseProfile
    registered: str
    socialProviders: str
    verified: str
    verifiedTimestamp: int
    newUser: bool
    sessionInfo: LoginResponseSessionInfo


class GetJWTResponse(TypedDict):
    callId: str
    errorCode: int
    apiVersion: int
    statusCode: int
    statusReason: str
    time: str
    id_token: str
