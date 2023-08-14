import random
import time
from types import TracebackType
from typing import Optional, Type
from urllib.parse import urljoin, urlparse, quote_plus
from aiohttp import ClientSession
from json import dumps as jsonstringify
import hmac
from base64 import b64decode, b64encode
from hashlib import sha1
from math import floor

from .gigyaModels import GetJWTResponse, LoginResponse, SocializeGetIdsResponse


def current_milli_time():
    return round(time.time() * 1000)


def UrlEncode(value):
    if value is None:
        return value
    elif isinstance(value, int):
        return str(value)
    else:
        if isinstance(value, dict) or isinstance(value, list):
            str_value = jsonstringify(value)
        else:
            str_value = value.encode("utf-8")

        return quote_plus(str_value).replace("+", "%20").replace("%7E", "~")


def buildQS(params: dict):
    """Converts a params dictionary to a sorted query string"""
    queryString = ""
    amp = ""
    # keys = params.keys()
    keys = list(params.keys())
    keys.sort()
    for key in keys:
        value = params.get(key)
        if value is not None:
            queryString += amp + key + "=" + UrlEncode(value)
            amp = "&"

    return queryString


def calcOAuth1BaseString(
    httpMethod: str, url: str, isSecureConnection: bool, requestParams: dict
):
    normalizedUrl = ""
    u = urlparse(url)

    if isSecureConnection:
        protocol = "https"
    else:
        protocol = u.scheme.lower()

    port = u.port

    normalizedUrl += protocol + "://"
    normalizedUrl += u.hostname.lower()

    if port != None and (
        (protocol == "http" and port != 80) or (protocol == "https" and port != 443)
    ):
        normalizedUrl += ":" + port

    normalizedUrl += u.path

    # Create a sorted list of query parameters
    queryString = buildQS(requestParams)

    # Construct the base string from the HTTP method, the URL and the parameters
    baseString = (
        httpMethod.upper()
        + "&"
        + UrlEncode(normalizedUrl)
        + "&"
        + UrlEncode(queryString)
    )

    return baseString


def calcSignature(baseString: str, secretKey: str):
    encodedBase = baseString.encode("utf-8")
    encodedKey = secretKey.encode("utf-8")
    rawHmac = hmac.new(b64decode(encodedKey), encodedBase, sha1).digest()
    signature = b64encode(rawHmac)
    return signature.decode("utf-8")


def getOAuth1Signature(
    secretKey: str,
    httpMethod: str,
    url: str,
    isSecureConnection: bool,
    requestParams: dict,
):
    # Taken from https://github.com/SAP/gigya-python-sdk/blob/main/GSSDK.py#L276
    # Create the BaseString.
    baseString = calcOAuth1BaseString(
        httpMethod, url, isSecureConnection, requestParams
    )

    return calcSignature(baseString, secretKey)


class GigyaClient:
    def __init__(
        self, domain: str, api_key: str, client_session: Optional[ClientSession] = None
    ) -> None:
        self._client_session = client_session
        self._close_session = False
        self._domain = domain
        self._api_key = api_key

    def _get_session(self):
        if self._client_session is None:
            self._client_session = ClientSession()
            self._close_session = True
        return self._client_session

    def _generate_nonce(self):
        return f"{current_milli_time()}_{random.randrange(1000000000, 10000000000)}"

    async def get_ids(self):
        # https://socialize.eu1.gigya.com/socialize.getIDs
        url = f"https://socialize.{self._domain}/socialize.getIDs"
        async with await self._get_session().get(
            url,
            data={
                "apiKey": self._api_key,
                "format": "json",
                "httpStatusCodes": False,
                "nonce": self._generate_nonce(),
                "sdk": "Android_6.2.1",
                "targetEnv": "mobile",
            },
        ) as response:
            data: SocializeGetIdsResponse = await response.json(content_type=None)
            return data

    async def login_session(self, username: str, password: str, gmid: str, ucid: str):
        # https://accounts.eu1.gigya.com/accounts.login
        url = f"https://accounts.{self._domain}/accounts.login"
        async with await self._get_session().post(
            url,
            data={
                "apiKey": self._api_key,
                "format": "json",
                "gmid": gmid,
                "httpStatusCodes": False,
                "loginID": username,
                "nonce": self._generate_nonce(),
                "password": password,
                "sdk": "Android_6.2.1",
                "targetEnv": "mobile",
                "ucid": ucid,
            },
        ) as response:
            data: LoginResponse = await response.json(content_type=None)
            return data

    async def get_JWT(
        self, sessionToken: str, sessionSecret: str, gmid: str, ucid: str
    ):
        # https://accounts.eu1.gigya.com/accounts.getJWT
        url = f"https://accounts.{self._domain}/accounts.getJWT"

        dataParams = {
            "apiKey": self._api_key,
            "fields": "country",
            "format": "json",
            "gmid": gmid,
            "httpStatusCodes": False,
            "nonce": self._generate_nonce(),
            "oauth_token": sessionToken,
            "sdk": "Android_6.2.1",
            "targetEnv": "mobile",
            "timestamp": floor(time.time()),
            "ucid": ucid,
        }
        dataParams["sig"] = getOAuth1Signature(
            sessionSecret, "POST", url, True, dataParams
        )

        async with await self._get_session().post(url, data=dataParams) as response:
            data: GetJWTResponse = await response.json(content_type=None)
            return data

    async def login_user(self, username: str, password: str):
        ids = await self.get_ids()
        gmid = ids["gmid"]
        ucid = ids["ucid"]
        session = await self.login_session(username, password, gmid, ucid)
        jwt = await self.get_JWT(
            session["sessionInfo"]["sessionToken"],
            session["sessionInfo"]["sessionSecret"],
            gmid,
            ucid,
        )
        return jwt

    async def close(self):
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
