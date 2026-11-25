"""The phone menu endpoint is unauthenticated to HA, so its own auth must hold."""
from __future__ import annotations

import base64
import re
import secrets
from unittest.mock import patch
from urllib.parse import parse_qsl, urlsplit
from xml.sax.saxutils import unescape

import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.yealink_xml import config_flow
import custom_components.yealink_xml as yealink
from custom_components.yealink_xml.const import DOMAIN

USERNAME = "phone"
PASSWORD = "correct horse"
PROFILE = "bedroom"
BASE_URL = "http://ha.test:8123"


def _basic(username: str = USERNAME, password: str = PASSWORD) -> dict[str, str]:
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


@pytest.fixture(autouse=True)
def _clear_credential_cache():
    yealink._VERIFIED_CREDENTIALS.clear()
    yield
    yealink._VERIFIED_CREDENTIALS.clear()


@pytest.fixture
async def client(hass, hass_client_no_auth):
    salt = secrets.token_hex(16)
    entry = MockConfigEntry(
        domain=DOMAIN,
        title="Bedroom phone",
        unique_id=PROFILE,
        data={
            "profile_id": PROFILE,
            "username": USERNAME,
            "password_salt": salt,
            "password_hash": config_flow._password_hash(PASSWORD, salt),
        },
        options={
            "profile_name": "Bedroom",
            "base_url": BASE_URL,
            "entities": ["light.desk"],
        },
    )
    hass.states.async_set("light.desk", "off", {"friendly_name": "Desk"})
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    return await hass_client_no_auth()


def _links(xml: str) -> list[str]:
    """Signed links as the phone would request them, relative to HA."""
    urls = [unescape(url) for url in re.findall(r"<URI>([^<]+)</URI>", xml)]
    return [url.removeprefix(BASE_URL) for url in urls if url.startswith(BASE_URL)]


async def test_menu_requires_credentials(client):
    response = await client.get(f"/api/yealink_xml/{PROFILE}?view=menu")
    assert response.status == 401
    assert "Basic" in response.headers["WWW-Authenticate"]

    response = await client.get(
        f"/api/yealink_xml/{PROFILE}?view=menu", headers=_basic(password="wrong")
    )
    assert response.status == 401


async def test_signed_links_work_without_credentials_and_expire(client):
    response = await client.get(f"/api/yealink_xml/{PROFILE}?view=menu", headers=_basic())
    assert response.status == 200
    links = _links(await response.text())
    assert links, "the menu should link to the selected entity"
    query = dict(parse_qsl(urlsplit(links[0]).query))
    assert {"sig", "exp"} <= query.keys()

    # Phones that drop the Authorization header can still follow the link.
    response = await client.get(links[0])
    assert response.status == 200

    # Changing any parameter invalidates the signature.
    response = await client.get(links[0].replace("light.desk", "light.other"))
    assert response.status == 401

    # A captured link stops working once it expires.
    expires = int(query["exp"])
    with patch.object(yealink.time, "time", return_value=expires + 1):
        response = await client.get(links[0])
    assert response.status == 401


async def test_links_without_expiry_are_rejected(client):
    response = await client.get(f"/api/yealink_xml/{PROFILE}?view=menu", headers=_basic())
    link = _links(await response.text())[0]
    parts = urlsplit(link)
    params = [(k, v) for k, v in parse_qsl(parts.query) if k not in ("exp", "sig")]
    entry = client.app["hass"].config_entries.async_entries(DOMAIN)[0]
    legacy_sig = yealink._signature(entry, parts.path, params)
    query = "&".join(f"{k}={v}" for k, v in params)
    response = await client.get(f"{parts.path}?{query}&sig={legacy_sig}")
    assert response.status == 401


async def test_password_hash_runs_once_per_session(client):
    calls = 0
    original = yealink._password_matches

    def counting(data, password):
        nonlocal calls
        calls += 1
        return original(data, password)

    with patch.object(yealink, "_password_matches", counting):
        for _ in range(3):
            response = await client.get(
                f"/api/yealink_xml/{PROFILE}?view=menu", headers=_basic()
            )
            assert response.status == 200
        # A wrong password is never answered from the cache.
        response = await client.get(
            f"/api/yealink_xml/{PROFILE}?view=menu", headers=_basic(password="nope")
        )
        assert response.status == 401
    assert calls == 2
