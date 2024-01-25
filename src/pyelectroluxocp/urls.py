from typing import Any, Dict, Mapping, Optional, Union
from urllib.parse import quote_plus, urljoin
from multidict import CIMultiDict, CIMultiDictProxy, istr

from .const import CLIENT_ID_ELECTROLUX


class RequestParams:
    def __init__(
        self,
        method: str,
        url: str,
        params: Optional[Mapping[str, str]] = None,
        headers: Optional[
            Union[
                Mapping[Union[str, istr], str], CIMultiDict[str], CIMultiDictProxy[str]
            ]
        ] = None,
        json: Any = None,
    ) -> None:
        self.method = method
        self.url = url
        self.params = params
        self.headers = headers
        self.json = json


def multi_urljoin(*parts: str):
    return urljoin(
        parts[0], "/".join(quote_plus(part.strip("/"), safe="/") for part in parts[1:])
    )


def token_url(
    base_url: str,
    headers: dict[str, str],
    grant_type: str,
    client_secret: str | None = None,
    id_token: str | None = None,
    refresh_token: str | None = None,
):
    # https://api.ocp.electrolux.one/one-account-authorization/api/v1/token
    return RequestParams(
        "POST",
        urljoin(base_url, "one-account-authorization/api/v1/token"),
        None,
        headers,
        {
            "grantType": grant_type,
            "clientId": CLIENT_ID_ELECTROLUX,
            "clientSecret": client_secret,
            "idToken": id_token,
            "refreshToken": refresh_token,
            "scope": "",
        },
    )


def identity_providers_url(
    base_url: str, headers: dict[str, str], brand: str, username: str
):
    # https://api.ocp.electrolux.one/one-account-user/api/v1/identity-providers?brand=electrolux&email={{username}}
    return RequestParams(
        "GET",
        urljoin(base_url, "one-account-user/api/v1/identity-providers"),
        {"brand": brand, "email": username},
        headers,
        None,
    )


def current_user_metadata_url(base_url: str, headers: dict[str, str]):
    # https://api.ocp.electrolux.one/one-account-user/api/v1/users/current
    return RequestParams(
        "GET",
        urljoin(base_url, "one-account-user/api/v1/identity-providers"),
        None,
        headers,
        None,
    )


def list_appliances_url(base_url: str, headers: dict[str, str], include_metadata: bool):
    # https://api.ocp.electrolux.one/appliance/api/v2/appliances?includeMetadata=true
    return RequestParams(
        "GET",
        urljoin(base_url, "appliance/api/v2/appliances"),
        {"includeMetadata": "true"} if include_metadata else None,
        headers,
        None,
    )


def get_appliance_by_id_url(
    baseUrl: str, headers: dict[str, str], id: str, include_metadata: bool
):
    # https://api.ocp.electrolux.one/appliance/api/v2/appliances/{{Id}}
    return RequestParams(
        "GET",
        multi_urljoin(baseUrl, "appliance/api/v2/appliances", id),
        {"includeMetadata": "true"} if include_metadata else None,
        headers,
        None,
    )


def get_appliance_capabilities_url(base_url: str, headers: dict[str, str], id: str):
    # https://api.ocp.electrolux.one/appliance/api/v2/appliances/{{Id}}/capabilities
    return RequestParams(
        "GET",
        multi_urljoin(base_url, "appliance/api/v2/appliances", id, "capabilities"),
        None,
        headers,
        None,
    )


def get_appliances_info_by_ids_url(
    base_url: str, headers: dict[str, str], ids: list[str]
):
    # POST https://api.ocp.electrolux.one/appliance/api/v2/appliances/info
    return RequestParams(
        "POST",
        multi_urljoin(base_url, "appliance/api/v2/appliances/info"),
        None,
        headers,
        {
            "applianceIds": ids,
        },
    )


def appliance_command_url(
    base_url: str, headers: dict[str, str], id: str, command_data: Dict[str, Any]
):
    # PUT https://api.ocp.electrolux.one/appliance/api/v2/appliances/{{Id}}/command
    return RequestParams(
        "PUT",
        multi_urljoin(base_url, "appliance/api/v2/appliances", id, "command"),
        None,
        headers,
        command_data,
    )
