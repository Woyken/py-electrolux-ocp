import logging
import random
import time
from types import TracebackType
from typing import Optional, Type
from urllib.parse import urlparse, quote_plus
from aiohttp import ClientResponse, ClientResponseError, ClientSession
from json import decoder, dumps as jsonstringify
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
    query_string = ""
    amp = ""
    # keys = params.keys()
    keys = list(params.keys())
    keys.sort()
    for key in keys:
        value = params.get(key)
        if value is not None:
            query_string += amp + key + "=" + UrlEncode(value)
            amp = "&"

    return query_string


def calcOAuth1BaseString(
    http_method: str, url: str, is_secure_connection: bool, request_params: dict
):
    normalized_url = ""
    u = urlparse(url)

    if is_secure_connection:
        protocol = "https"
    else:
        protocol = u.scheme.lower()

    port = u.port

    normalized_url += protocol + "://"
    if u.hostname is None:
        raise Exception("hostname is expected to always not be None")
    normalized_url += u.hostname.lower()

    if port != None and (
        (protocol == "http" and port != 80) or (protocol == "https" and port != 443)
    ):
        normalized_url += ":" + str(port)

    normalized_url += u.path

    # Create a sorted list of query parameters
    query_string = buildQS(request_params)

    # Construct the base string from the HTTP method, the URL and the parameters
    base_string = (
        http_method.upper()
        + "&"
        + UrlEncode(normalized_url)
        + "&"
        + UrlEncode(query_string)
    )

    return base_string


def calcSignature(base_string: str, secret_key: str):
    encoded_base = base_string.encode("utf-8")
    encoded_key = secret_key.encode("utf-8")
    raw_hmac = hmac.new(b64decode(encoded_key), encoded_base, sha1).digest()
    signature = b64encode(raw_hmac)
    return signature.decode("utf-8")


def getOAuth1Signature(
    secret_key: str,
    http_method: str,
    url: str,
    is_secure_connection: bool,
    request_params: dict,
):
    # Taken from https://github.com/SAP/gigya-python-sdk/blob/main/GSSDK.py#L276
    # Create the BaseString.
    base_string = calcOAuth1BaseString(
        http_method, url, is_secure_connection, request_params
    )

    return calcSignature(base_string, secret_key)


_LOGGER: logging.Logger = logging.getLogger(__package__).getChild("GigyaClient")


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

    async def try_parse_json_from_response(self, client_response: ClientResponse):
        if (
            client_response.content_length is None
            or client_response.content_length <= 0
        ):
            _LOGGER.error("Empty response received!")
            client_response.raise_for_status()
            raise LoginError(
                f"Error during login. Empty response body. ResponseStatus: {client_response.status}"
            )

        try:
            response_json = await client_response.json(content_type=None)
            return response_json
        except decoder.JSONDecodeError:
            _LOGGER.error("Failed to parse JSON!")
            response_text = await client_response.text()
            if not client_response.ok:
                responseError = ClientResponseError(
                    client_response.request_info,
                    client_response.history,
                    status=client_response.status,
                    message=(
                        "" if client_response.reason is None else client_response.reason
                    ),
                    headers=client_response.headers,
                )
                raise LoginError(
                    f"Error during login. {responseError!r}. Response body: ({response_text})"
                )
            raise LoginError(
                f"Error during login. Status OK, but response not JSON. ResponseStatus: {client_response.status}, url: {client_response.request_info.real_url}, headers: {client_response.headers!r}, response body: ({response_text})"
            )

    async def get_ids(self):
        # https://socialize.eu1.gigya.com/socialize.getIDs
        _LOGGER.debug("get_ids()")
        url = f"https://socialize.{self._domain}/socialize.getIDs"
        async with await self._get_session().post(
            url,
            data={
                "apiKey": self._api_key,
                "format": "json",
                "httpStatusCodes": True,
                "nonce": self._generate_nonce(),
                "sdk": "Android_6.2.1",
                "targetEnv": "mobile",
            },
        ) as response:
            _LOGGER.debug(
                "get_ids(), response, requestUlr: %s, requestHeaders: %s, responseStatus: %i, responseHeaders: %s",
                response.request_info.url,
                response.request_info.headers,
                response.status,
                response.headers,
            )
            response_json = await self.try_parse_json_from_response(response)
            _LOGGER.debug(
                "get_ids(), response, json: %s",
                response_json,
            )
            response.raise_for_status()
            data: SocializeGetIdsResponse = response_json
            return data

    async def login_session(self, username: str, password: str, gmid: str, ucid: str):
        # https://accounts.eu1.gigya.com/accounts.login
        _LOGGER.debug(
            "login_session(), username: %s, gmid: %s, ucid: %s", username, gmid, ucid
        )
        url = f"https://accounts.{self._domain}/accounts.login"
        async with await self._get_session().post(
            url,
            data={
                "apiKey": self._api_key,
                "format": "json",
                "gmid": gmid,
                "httpStatusCodes": True,
                "loginID": username,
                "nonce": self._generate_nonce(),
                "password": password,
                "sdk": "Android_6.2.1",
                "targetEnv": "mobile",
                "ucid": ucid,
            },
        ) as response:
            _LOGGER.debug(
                "login_session(), response, requestUlr: %s, requestHeaders: %s, responseStatus: %i, responseHeaders: %s",
                response.request_info.url,
                response.request_info.headers,
                response.status,
                response.headers,
            )
            response_json = await self.try_parse_json_from_response(response)
            _LOGGER.debug(
                "login_session(), response, json: %s",
                response_json,
            )
            response.raise_for_status()
            data: LoginResponse = response_json
            return data

    async def get_JWT(
        self, session_token: str, session_secret: str, gmid: str, ucid: str
    ):
        # https://accounts.eu1.gigya.com/accounts.getJWT
        _LOGGER.debug("get_JWT(), gmid: %s, ucid: %s", gmid, ucid)
        url = f"https://accounts.{self._domain}/accounts.getJWT"

        data_params = {
            "apiKey": self._api_key,
            "fields": "country",
            "format": "json",
            "gmid": gmid,
            "httpStatusCodes": True,
            "nonce": self._generate_nonce(),
            "oauth_token": session_token,
            "sdk": "Android_6.2.1",
            "targetEnv": "mobile",
            "timestamp": floor(time.time()),
            "ucid": ucid,
        }
        data_params["sig"] = getOAuth1Signature(
            session_secret, "POST", url, True, data_params
        )

        async with await self._get_session().post(url, data=data_params) as response:
            _LOGGER.debug(
                "get_JWT(), response, requestUlr: %s, requestHeaders: %s, responseStatus: %i, responseHeaders: %s",
                response.request_info.url,
                response.request_info.headers,
                response.status,
                response.headers,
            )
            response_json = await self.try_parse_json_from_response(response)
            _LOGGER.debug(
                "get_JWT(), response, json: %s",
                jsonstringify(response_json),
            )
            response.raise_for_status()
            data: GetJWTResponse = response_json
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


class LoginError(Exception):
    """Raised when login fails"""

    pass
