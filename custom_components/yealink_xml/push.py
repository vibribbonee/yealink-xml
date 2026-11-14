"""Push text and sound notifications to Yealink XML Browser phones."""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET

from aiohttp import BasicAuth, ClientError, ClientTimeout
import voluptuous as vol
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import (
    ATTR_NOTIFICATION_BEEP,
    ATTR_NOTIFICATION_MESSAGE,
    ATTR_NOTIFICATION_RING,
    ATTR_NOTIFICATION_TIMEOUT,
    ATTR_NOTIFICATION_TITLE,
    ATTR_PHONE_ENTRY_ID,
    CONF_BASE_URL,
    CONF_PHONE_PASSWORD,
    CONF_PHONE_URL,
    CONF_PHONE_USERNAME,
    CONF_PHONE_VERIFY_SSL,
    CONF_PROFILE_ID,
    DOMAIN,
    SERVICE_PUSH_NOTIFICATION,
)

_LOGGER = logging.getLogger(__name__)

PUSH_NOTIFICATION_SCHEMA = vol.Schema(
    {
        vol.Required(ATTR_PHONE_ENTRY_ID): cv.string,
        vol.Required(ATTR_NOTIFICATION_MESSAGE): vol.All(
            cv.string, vol.Length(min=1, max=4000)
        ),
        vol.Optional(ATTR_NOTIFICATION_TITLE, default="Home Assistant"): vol.All(
            cv.string, vol.Length(max=128)
        ),
        vol.Optional(ATTR_NOTIFICATION_BEEP, default=True): cv.boolean,
        vol.Optional(ATTR_NOTIFICATION_RING, default=False): cv.boolean,
        vol.Optional(ATTR_NOTIFICATION_TIMEOUT, default=15): vol.All(
            vol.Coerce(int), vol.Range(min=5, max=120)
        ),
    }
)


def register_push_notification_service(hass: HomeAssistant) -> None:
    """Register the service used by scripts and automations to notify a phone."""

    async def async_push_notification(call: ServiceCall) -> None:
        """Push a Yealink TextScreen object to one configured phone."""
        phone_entry_id = str(call.data[ATTR_PHONE_ENTRY_ID]).strip()
        entry = next(
            (
                candidate
                for candidate in hass.config_entries.async_entries(DOMAIN)
                if candidate.entry_id == phone_entry_id
            ),
            None,
        )
        if entry is None:
            raise HomeAssistantError(
                "The selected Yealink phone profile is no longer available; select it again"
            )
        profile_id = str(entry.data.get(CONF_PROFILE_ID) or "default")

        options = entry.options
        phone_url = str(options.get(CONF_PHONE_URL, "")).rstrip("/")
        username = str(options.get(CONF_PHONE_USERNAME, ""))
        password = str(options.get(CONF_PHONE_PASSWORD, ""))
        if not phone_url or not username or not password:
            raise HomeAssistantError(
                "Configure the phone URL and web-interface credentials in the Yealink profile first"
            )

        title = _clean_xml_text(str(call.data[ATTR_NOTIFICATION_TITLE]))
        message = _clean_xml_text(str(call.data[ATTR_NOTIFICATION_MESSAGE]))
        if not message.strip():
            raise HomeAssistantError("The Yealink notification message cannot be empty")

        beep = bool(call.data[ATTR_NOTIFICATION_BEEP])
        ring = bool(call.data[ATTR_NOTIFICATION_RING])
        timeout = int(call.data[ATTR_NOTIFICATION_TIMEOUT])
        xml = _build_text_screen(title or "Home Assistant", message, beep, ring, timeout)

        session = async_get_clientsession(
            hass, verify_ssl=bool(options.get(CONF_PHONE_VERIFY_SSL, True))
        )
        headers = {"Content-Type": "text/xml"}
        if base_url := str(options.get(CONF_BASE_URL, "")):
            headers["Referer"] = base_url.rstrip("/")
        try:
            async with session.post(
                f"{phone_url}/servlet",
                params={"push": "xml"},
                data=b"xml=" + xml,
                headers=headers,
                auth=BasicAuth(username, password),
                timeout=ClientTimeout(total=10),
                allow_redirects=False,
            ) as response:
                if not 200 <= response.status < 300:
                    raise HomeAssistantError(
                        f"Yealink phone returned HTTP {response.status} while receiving the notification"
                    )
        except (ClientError, TimeoutError, UnicodeError) as err:
            _LOGGER.warning(
                "Could not push a notification to Yealink profile %s: %s",
                profile_id,
                err,
            )
            raise HomeAssistantError(
                "Could not deliver the notification to the Yealink phone; check its address and Push XML allowlist"
            ) from err

    hass.services.async_register(
        DOMAIN,
        SERVICE_PUSH_NOTIFICATION,
        async_push_notification,
        schema=PUSH_NOTIFICATION_SCHEMA,
    )


def _clean_xml_text(value: str) -> str:
    """Remove characters that XML 1.0 cannot represent."""
    return "".join(
        char
        for char in value
        if char in "\t\n\r"
        or 0x20 <= ord(char) <= 0xD7FF
        or 0xE000 <= ord(char) <= 0xFFFD
        or 0x10000 <= ord(char) <= 0x10FFFF
    )


def _build_text_screen(
    title: str,
    message: str,
    beep: bool,
    ring: bool,
    timeout: int,
) -> bytes:
    """Build a bounded Yealink TextScreen XML object."""
    attributes = {
        "Beep": "yes" if beep or ring else "no",
        # Yealink's documented default is Ring1.wav. Set Silent.wav explicitly
        # so the beep-only option does not turn into a ringtone on the phone.
        "Ring": "Ring1.wav" if ring else "Silent.wav",
        "Timeout": str(timeout),
        "LockIn": "no",
    }

    root = ET.Element("YealinkIPPhoneTextScreen", attributes)
    ET.SubElement(root, "Title", {"wrap": "yes"}).text = title
    text_element = ET.SubElement(root, "Text")
    text_element.text = message
    if len(ET.tostring(text_element, encoding="utf-8")) > 1900:
        raise HomeAssistantError(
            "The Yealink notification message is too long; keep it below 1,900 encoded bytes"
        )

    return b'<?xml version="1.0" encoding="UTF-8"?>' + ET.tostring(
        root, encoding="utf-8", short_empty_elements=True
    )
