"""Buttons for controlling a Yealink phone over its local Action URI endpoint."""

from __future__ import annotations

import logging

from aiohttp import BasicAuth, ClientError, ClientTimeout
from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import (
    CONF_PHONE_ACTIONS,
    CONF_PHONE_PASSWORD,
    CONF_PHONE_URL,
    CONF_PHONE_USERNAME,
    CONF_PHONE_VERIFY_SSL,
    DEFAULT_PHONE_ACTIONS,
    DOMAIN,
    PHONE_ACTIONS,
)

_LOGGER = logging.getLogger(__name__)

# Current Yealink firmware uses /servlet. Some firmware/web-server variants
# retain the two legacy Action URI endpoints documented by Yealink.
_ACTION_URI_PATHS = (
    "/servlet",
    "/cgi-bin/ConfigManApp.com",
    "/cgi-bin/cgiServer.exx",
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the configured Yealink phone action buttons."""
    options = entry.options
    phone_url = str(options.get(CONF_PHONE_URL, "")).rstrip("/")
    username = str(options.get(CONF_PHONE_USERNAME, ""))
    password = str(options.get(CONF_PHONE_PASSWORD, ""))
    verify_ssl = bool(options.get(CONF_PHONE_VERIFY_SSL, True))
    if not phone_url or not username or not password:
        return

    configured_actions = options.get(CONF_PHONE_ACTIONS, DEFAULT_PHONE_ACTIONS)
    actions = [action for action in configured_actions if action in PHONE_ACTIONS]
    if not actions:
        return

    async_add_entities(
        YealinkActionButton(
            entry,
            phone_url,
            username,
            password,
            verify_ssl,
            action_id,
        )
        for action_id in actions
    )


class YealinkActionButton(ButtonEntity):
    """Send one documented Yealink Action URI key to a phone."""

    _attr_has_entity_name = True
    _attr_should_poll = False

    def __init__(
        self,
        entry: ConfigEntry,
        phone_url: str,
        username: str,
        password: str,
        verify_ssl: bool,
        action_id: str,
    ) -> None:
        """Initialize a phone action button."""
        self._entry = entry
        self._phone_url = phone_url
        self._username = username
        self._password = password
        self._verify_ssl = verify_ssl
        self._action_id = action_id
        self._action_name, self._action_key = PHONE_ACTIONS[action_id]
        self._attr_unique_id = f"{entry.entry_id}_{action_id}"
        self._attr_name = self._action_name
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name=entry.title,
            manufacturer="Yealink",
        )

    async def async_press(self) -> None:
        """Send the selected action to the configured phone."""
        session = async_get_clientsession(self.hass, verify_ssl=self._verify_ssl)
        try:
            for index, path in enumerate(_ACTION_URI_PATHS):
                async with session.get(
                    f"{self._phone_url}{path}",
                    params={"key": self._action_key},
                    auth=BasicAuth(self._username, self._password),
                    timeout=ClientTimeout(total=10),
                    allow_redirects=False,
                ) as response:
                    if response.status == 404 and index < len(_ACTION_URI_PATHS) - 1:
                        _LOGGER.debug(
                            "Yealink Action URI endpoint %s returned 404 for profile %s; trying its documented compatibility path",
                            path,
                            self._entry.entry_id,
                        )
                        continue
                    if not 200 <= response.status < 300:
                        raise HomeAssistantError(
                            f"Yealink phone returned HTTP {response.status}"
                        )
                    return
        except (ClientError, TimeoutError, UnicodeError) as err:
            _LOGGER.warning(
                "Could not send Yealink action %s for profile %s: %s",
                self._action_id,
                self._entry.entry_id,
                err,
            )
            raise HomeAssistantError(
                f"Could not send {self._action_name} to the Yealink phone"
            ) from err
