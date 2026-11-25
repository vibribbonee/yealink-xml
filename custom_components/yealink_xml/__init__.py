"""Yealink XML Browser endpoints for Home Assistant."""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import hmac
import logging
import time
from collections import OrderedDict
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit
import xml.etree.ElementTree as ET

from aiohttp import web
from homeassistant.const import Platform
from homeassistant.components.http import HomeAssistantView, KEY_HASS
from homeassistant.components.media_player.const import MediaPlayerEntityFeature
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import config_validation as cv

from .const import (
    CHOICE_PAGE_SIZE,
    CONF_BASE_URL,
    CONF_ENTITIES,
    CONF_TAP_BEHAVIOR,
    CONF_AFTER_ACTION,
    CONF_SHOW_CONTROLS_ENTRY,
    CONF_STATE_WAIT,
    TAP_BEHAVIOR_MENU,
    TAP_BEHAVIOR_TOGGLE,
    AFTER_ACTION_ENTITY,
    DEFAULT_TAP_BEHAVIOR,
    DEFAULT_AFTER_ACTION,
    DEFAULT_SHOW_CONTROLS_ENTRY,
    DEFAULT_STATE_WAIT,
    CONF_PASSWORD_HASH,
    CONF_PASSWORD_SALT,
    CONF_PROFILE_ID,
    CONF_PROFILE_NAME,
    CONF_USERNAME,
    DOMAIN,
    ENTITY_PAGE_SIZE,
    MAX_XML_BYTES,
    ROOT_PAGE_SIZE,
    VIEW_PATH,
)
from .push import register_push_notification_service

_LOGGER = logging.getLogger(__name__)
CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)


async def async_setup(hass: HomeAssistant, config: dict[str, Any]) -> bool:
    """Register the HTTP route once; it reads active config-entry options per request."""
    hass.http.register_view(YealinkXmlView())
    hass.http.register_view(YealinkXmlProfileView())
    register_push_notification_service(hass)
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up the integration config entry."""
    entry.async_on_unload(entry.add_update_listener(_async_update_listener))
    await hass.config_entries.async_forward_entry_setups(entry, [Platform.BUTTON])
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload phone action entities for this profile."""
    return await hass.config_entries.async_unload_platforms(entry, [Platform.BUTTON])


async def _async_update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Reload platforms when profile options or phone credentials change."""
    await hass.config_entries.async_reload(entry.entry_id)


# Signed menu links stay valid this long. Menus are re-signed on every
# response, so only a page left on screen for longer needs reopening.
SIGNED_LINK_LIFETIME = 24 * 60 * 60
# Remember recently verified phone credentials so each menu tap does not repeat
# the deliberately slow password hash. Keys are digests, never the password.
_VERIFIED_CREDENTIALS: OrderedDict[bytes, float] = OrderedDict()
_VERIFIED_CREDENTIAL_SECONDS = 10 * 60
_MAX_VERIFIED_CREDENTIALS = 32


def _basic_credentials(request: web.Request) -> tuple[str, str] | None:
    """Return the request's Basic Auth username and password, if well-formed."""
    authorization = request.headers.get("Authorization", "")
    scheme, separator, encoded = authorization.partition(" ")
    if not separator or scheme.lower() != "basic" or not encoded:
        return None
    try:
        decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    username, separator, password = decoded.partition(":")
    if not separator:
        return None
    return username, password


def _password_matches(entry_data: dict[str, Any], password: str) -> bool:
    """Compare a password with the stored PBKDF2 hash. Slow by design."""
    try:
        salt = bytes.fromhex(str(entry_data[CONF_PASSWORD_SALT]))
    except (KeyError, ValueError):
        return False
    actual_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, 150_000
    ).hex()
    return hmac.compare_digest(actual_hash, str(entry_data.get(CONF_PASSWORD_HASH, "")))


def _credential_key(entry: ConfigEntry, username: str, password: str) -> bytes:
    """Bind a cache entry to these credentials and the entry's current hash."""
    return hashlib.sha256(
        b"\0".join((
            entry.entry_id.encode(),
            str(entry.data.get(CONF_PASSWORD_HASH, "")).encode(),
            username.encode("utf-8"),
            password.encode("utf-8"),
        ))
    ).digest()


async def _async_verify_basic_auth(
    hass: HomeAssistant, request: web.Request, entry: ConfigEntry
) -> bool:
    """Verify the phone's Basic Auth without blocking Home Assistant's event loop."""
    credentials = _basic_credentials(request)
    if credentials is None:
        return False
    username, password = credentials
    if not hmac.compare_digest(username, str(entry.data.get(CONF_USERNAME, ""))):
        return False
    key = _credential_key(entry, username, password)
    now = time.monotonic()
    verified_at = _VERIFIED_CREDENTIALS.get(key)
    if verified_at is not None and now - verified_at < _VERIFIED_CREDENTIAL_SECONDS:
        return True
    if not await hass.async_add_executor_job(_password_matches, dict(entry.data), password):
        return False
    _VERIFIED_CREDENTIALS[key] = now
    _VERIFIED_CREDENTIALS.move_to_end(key)
    while len(_VERIFIED_CREDENTIALS) > _MAX_VERIFIED_CREDENTIALS:
        _VERIFIED_CREDENTIALS.popitem(last=False)
    return True


def _link_signing_key(entry: ConfigEntry) -> bytes:
    """Derive a per-profile signing key without storing another plaintext secret.

    Yealink firmware can be inconsistent about re-sending XML Basic Auth for
    each menu-item URI. Signed, narrowly-scoped URLs allow navigation to work
    even when the phone omits Authorization on a follow-up GET.
    """
    data = entry.data
    salt = str(data.get(CONF_PASSWORD_SALT, "")).encode("utf-8")
    password_hash = str(data.get(CONF_PASSWORD_HASH, "")).encode("utf-8")
    return hashlib.sha256(b"yealink-xml-link-v1\0" + salt + b"\0" + password_hash).digest()


def _canonical_request(path: str, params: list[tuple[str, str]]) -> bytes:
    """Canonicalize a path and query parameters for a signed link."""
    filtered = [(key, value) for key, value in params if key != "sig"]
    filtered.sort()
    query = urlencode(filtered)
    return (path + ("?" + query if query else "")).encode("utf-8")


def _signature(entry: ConfigEntry, path: str, params: list[tuple[str, str]]) -> str:
    """Return an HMAC for this exact path and query, binding action parameters."""
    return hmac.new(_link_signing_key(entry), _canonical_request(path, params), hashlib.sha256).hexdigest()


def _signed_url(url: str, entry: ConfigEntry) -> str:
    """Append an HMAC signature to a same-server XML navigation URL."""
    parts = urlsplit(url)
    params = [
        (key, value)
        for key, value in parse_qsl(parts.query, keep_blank_values=True)
        if key not in ("sig", "exp")
    ]
    params.append(("exp", str(int(time.time()) + SIGNED_LINK_LIFETIME)))
    params.append(("sig", _signature(entry, parts.path, params)))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(params), parts.fragment))


def _sign_xml_links(xml: str, entry: ConfigEntry) -> str:
    """Sign every navigation/action link in a rendered Yealink XML object."""
    try:
        root = ET.fromstring(xml)
        for attr in ("previous", "cancelAction", "url"):
            value = root.attrib.get(attr)
            if value and value.startswith(("http://", "https://")):
                root.attrib[attr] = _signed_url(value, entry)
        for element in root.iter():
            if element.tag.rsplit("}", 1)[-1] == "URI" and element.text:
                value = element.text.strip()
                if value.startswith(("http://", "https://")):
                    element.text = _signed_url(value, entry)
        return '<?xml version="1.0" encoding="UTF-8"?>' + ET.tostring(
            root, encoding="unicode", short_empty_elements=True
        )
    except (ET.ParseError, ValueError):
        _LOGGER.exception("Failed to sign XML navigation links")
        return xml


def _verify_signed_request(request: web.Request, entry: ConfigEntry) -> bool:
    """Verify an HMAC-authenticated link when the phone omits Basic Auth."""
    supplied = request.query.get("sig", "")
    if len(supplied) != 64:
        return False
    try:
        expires = int(request.query.get("exp", ""))
    except ValueError:
        # Links from older releases had no expiry; the phone reopens the menu
        # with Basic Auth, which issues fresh, expiring links.
        return False
    if expires < time.time():
        return False
    # Use the URL's decoded query parameters, canonicalized in the same way as
    # _signed_url. Duplicate parameters are included rather than silently lost.
    params = parse_qsl(request.rel_url.query_string, keep_blank_values=True)
    expected = _signature(entry, request.rel_url.path, params)
    return hmac.compare_digest(supplied, expected)


def _int_query(request: web.Request, key: str, default: int = 0) -> int:
    """Read a non-negative integer query parameter safely."""
    try:
        return max(0, int(request.query.get(key, default)))
    except (TypeError, ValueError):
        return default


def _state_snapshot(state: Any | None) -> tuple[str, dict[str, Any]] | None:
    """Capture visible state and attributes so attribute-only updates count too."""
    if state is None:
        return None
    return state.state, dict(state.attributes)


def _should_wait_for_state_update(state: Any, action_id: str) -> bool:
    """Skip waiting for trigger-style actions that don't update their own entity."""
    domain = state.entity_id.split(".", 1)[0]

    # These actions affect other entities or have no reliable persistent state
    # on the selected entity itself.
    if (domain == "scene" and action_id == "activate") or (
        domain == "automation" and action_id == "automation_trigger"
    ):
        return False
    if domain == "script" and action_id == "run":
        return False
    if domain in {"button", "input_button"} and action_id == "press":
        return False

    # An idempotent request already matching the reported state cannot produce a
    # useful state transition; don't make the user wait for an update that won't come.
    if action_id in {"turn_on", "automation_enable", "media_on", "water_on"} and state.state == "on":
        return False
    if action_id in {"turn_off", "automation_disable", "media_off", "water_off"} and state.state == "off":
        return False
    if action_id == "open" and state.state in {"open", "opening"}:
        return False
    if action_id == "close" and state.state in {"closed", "closing"}:
        return False
    if action_id == "lock" and state.state in {"locked", "locking"}:
        return False
    if action_id == "unlock" and state.state in {"unlocked", "unlocking"}:
        return False
    return True


async def _wait_for_entity_update(
    hass: HomeAssistant,
    entity_id: str,
    previous_snapshot: tuple[str, dict[str, Any]] | None,
    timeout: float,
) -> bool:
    """Wait briefly for a service's state update before rendering the next menu.

    Returns early as soon as state or attributes change. If a device is slow or
    doesn't report a change, it stops at the configured timeout so the phone
    doesn't wait indefinitely.
    """
    if timeout <= 0:
        return False
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        current_snapshot = _state_snapshot(hass.states.get(entity_id))
        if current_snapshot is not None and current_snapshot != previous_snapshot:
            return True
        remaining = deadline - loop.time()
        if remaining <= 0:
            return False
        await asyncio.sleep(min(0.1, remaining))


def _configured_state_wait(value: Any) -> float:
    """Read the configured max state-refresh wait, bounded to a safe range."""
    try:
        return min(5.0, max(0.0, float(value)))
    except (TypeError, ValueError):
        return float(DEFAULT_STATE_WAIT)


def _url(endpoint_url: str, **query: Any) -> str:
    """Build an absolute URL for a given phone-profile endpoint."""
    return f"{endpoint_url.rstrip('/')}?{urlencode(query)}"


def _short(value: Any, limit: int = 75) -> str:
    """Make values safe and legible on small phone displays."""
    text = " ".join(str(value).replace("\x00", "").split())
    if len(text) > limit:
        return text[: limit - 1] + "…"
    return text


def _menu_state_label(state: Any) -> str:
    """Return a compact state summary that is more useful than raw state alone."""
    domain = state.entity_id.split(".", 1)[0]
    attrs = state.attributes
    current = str(state.state)

    if current in {"unknown", "unavailable", "none"}:
        return current.title()

    if domain == "light":
        if current == "on" and isinstance(attrs.get("brightness"), (int, float)):
            percent = round(float(attrs["brightness"]) * 100 / 255)
            return f"On · {percent}%"
        return "On" if current == "on" else "Off" if current == "off" else current

    if domain == "cover":
        position = attrs.get("current_position")
        if isinstance(position, (int, float)):
            return f"{current.title()} · {round(position)}%"

    if domain == "climate":
        target = attrs.get("temperature")
        unit = attrs.get("temperature_unit", "°")
        if isinstance(target, (int, float)):
            return f"{current.title()} · {target:g}{unit}"

    if domain == "media_player":
        title = attrs.get("media_title")
        if title and current in {"playing", "paused", "buffering"}:
            return f"{current.title()} · {_short(title, 28)}"

    if domain in {"sensor", "binary_sensor", "number", "input_number"}:
        unit = attrs.get("unit_of_measurement")
        if unit:
            return f"{current} {unit}"

    return current


def _xml_menu(
    title: str,
    items: list[tuple[str, str]],
    *,
    base_url: str,
    previous: str | None = None,
) -> str:
    """Render one Yealink TextMenu XML object."""
    root_attrs = {
        "style": "numbered",
        "Beep": "no",
        "Timeout": "60",
        "LockIn": "no",
    }
    if previous:
        root_attrs["previous"] = previous
    root = ET.Element("YealinkIPPhoneTextMenu", root_attrs)
    ET.SubElement(root, "Title", {"wrap": "yes"}).text = _short(title, 80)
    for prompt, uri in items[:29]:
        menu_item = ET.SubElement(root, "MenuItem")
        ET.SubElement(menu_item, "Prompt").text = _short(prompt, 85)
        ET.SubElement(menu_item, "URI").text = uri
    if not items:
        item = ET.SubElement(root, "MenuItem")
        ET.SubElement(item, "Prompt").text = "No items"
        ET.SubElement(item, "URI").text = _url(base_url, view="menu")
    xml = '<?xml version="1.0" encoding="UTF-8"?>' + ET.tostring(
        root, encoding="unicode", short_empty_elements=True
    )
    encoded_len = len(xml.encode("utf-8"))
    if encoded_len > MAX_XML_BYTES:
        # Keep the phone within Yealink's documented XML size limit by reducing
        # an exceptionally large item list. Normal pages are capped below 30.
        return _xml_menu(
            _short(title, 50),
            [
                ("XML too large; open a smaller page", _url(base_url, view="menu")),
                ("Return to menu", _url(base_url, view="menu")),
            ],
            base_url=base_url,
            previous=previous,
        )
    return xml


def _domain_label(domain: str) -> str:
    """Return a phone-friendly domain label."""
    known = {
        "binary_sensor": "Binary sensors",
        "input_boolean": "Input booleans",
        "input_button": "Input buttons",
        "input_datetime": "Input date/time",
        "input_number": "Input numbers",
        "input_select": "Input selects",
        "input_text": "Input text",
        "media_player": "Media players",
        "person": "People",
        "sun": "Sun",
        "todo": "To-do lists",
        "water_heater": "Water heaters",
    }
    return known.get(domain, domain.replace("_", " ").title() + "s")


def _display_name(state: Any) -> str:
    """Get a display name from state attributes."""
    return str(state.attributes.get("friendly_name") or state.entity_id)


def _entity_rows(hass: HomeAssistant, selected: list[str]) -> list[Any]:
    """Return selected entities in the exact order chosen in the profile options."""
    states = []
    seen: set[str] = set()
    for entity_id in selected:
        if entity_id in seen:
            continue
        seen.add(entity_id)
        if (state := hass.states.get(entity_id)) is not None:
            states.append(state)
    return states


def _available_actions(state: Any) -> dict[str, dict[str, Any]]:
    """Build a strict allowlist of actions available for the current entity state."""
    entity_id = state.entity_id
    domain = entity_id.split(".", 1)[0]
    attrs = state.attributes
    result: dict[str, dict[str, Any]] = {}

    def add(
        action_id: str,
        label: str,
        service: str,
        extra: dict[str, Any] | None = None,
        service_domain: str | None = None,
    ) -> None:
        result[action_id] = {
            "label": label,
            "domain": service_domain or domain,
            "service": service,
            "data": extra or {},
        }

    if domain in {"light", "switch", "input_boolean", "fan", "humidifier", "siren", "remote"}:
        add("turn_on", "Turn on", "turn_on")
        add("turn_off", "Turn off", "turn_off")
        add("toggle", "Toggle", "toggle")

    if domain == "light" and state.state == "on":
        add("brightness_down", "Dim 20%", "turn_on", {"_brightness_delta": -51})
        add("brightness_up", "Brighten 20%", "turn_on", {"_brightness_delta": 51})

    if domain == "fan":
        percentage = attrs.get("percentage")
        try:
            percentage = int(percentage)
        except (TypeError, ValueError):
            percentage = None
        if percentage is not None:
            add("speed_down", "Fan speed −20%", "set_percentage", {"_percentage_delta": -20})
            add("speed_up", "Fan speed +20%", "set_percentage", {"_percentage_delta": 20})
        preset_modes = attrs.get("preset_modes", [])
        if isinstance(preset_modes, list):
            for index, mode in enumerate(preset_modes[:12]):
                add(f"choose_fan_preset_{index}", f"Preset: {_short(mode, 42)}", "set_preset_mode", {"preset_mode": mode})

    if domain == "automation":
        add("automation_enable", "Enable automation", "turn_on")
        add("automation_disable", "Disable automation", "turn_off")
        add("automation_trigger", "Run automation now", "trigger")
    elif domain in {"scene"}:
        add("activate", "Activate scene", "turn_on")
    elif domain == "script":
        add("run", "Run script", "turn_on")
        add("stop", "Stop script", "turn_off")
    elif domain == "button":
        add("press", "Press button", "press")
    elif domain == "input_button":
        add("press", "Press input button", "press")
    elif domain == "cover":
        add("open", "Open", "open_cover")
        add("stop", "Stop", "stop_cover")
        add("close", "Close", "close_cover")
        position = attrs.get("current_position")
        if isinstance(position, (int, float)):
            add("position_down", "Close by 20%", "set_cover_position", {"_position_delta": -20})
            add("position_up", "Open by 20%", "set_cover_position", {"_position_delta": 20})
    elif domain == "valve":
        add("open", "Open valve", "open_valve")
        add("stop", "Stop valve", "stop_valve")
        add("close", "Close valve", "close_valve")
    elif domain == "lock":
        add("lock", "Lock", "lock")
        add("unlock", "Unlock", "unlock")
    elif domain == "climate":
        modes = attrs.get("hvac_modes", [])
        if isinstance(modes, list):
            for index, mode in enumerate(modes[:12]):
                add(f"hvac_mode_{index}", f"Mode: {mode}", "set_hvac_mode", {"hvac_mode": mode})
        target = attrs.get("temperature")
        if isinstance(target, (float, int)) and not isinstance(target, bool):
            step = attrs.get("target_temp_step", 1)
            try:
                step = float(step)
            except (TypeError, ValueError):
                step = 1.0
            minimum = attrs.get("min_temp", target - 10)
            maximum = attrs.get("max_temp", target + 10)
            try:
                minimum, maximum = float(minimum), float(maximum)
            except (TypeError, ValueError):
                minimum, maximum = target - 10, target + 10
            add("temp_down", f"Temperature −{step:g}°", "set_temperature", {"_temperature_delta": -step})
            add("temp_up", f"Temperature +{step:g}°", "set_temperature", {"_temperature_delta": step})
            add("climate_off", "HVAC off", "set_hvac_mode", {"hvac_mode": "off"})
        for attr_name, action_prefix, service_name, label_prefix, data_key in (
            ("fan_modes", "choose_climate_fan_", "set_fan_mode", "Fan", "fan_mode"),
            ("preset_modes", "choose_climate_preset_", "set_preset_mode", "Preset", "preset_mode"),
            ("swing_modes", "choose_climate_swing_", "set_swing_mode", "Swing", "swing_mode"),
        ):
            modes = attrs.get(attr_name, [])
            if isinstance(modes, list):
                for index, mode in enumerate(modes[:12]):
                    add(f"{action_prefix}{index}", f"{label_prefix}: {_short(mode, 42)}", service_name, {data_key: mode})

    elif domain == "humidifier":
        target = attrs.get("humidity")
        if isinstance(target, (int, float)):
            add("humidity_down", "Humidity −5%", "set_humidity", {"_humidity_delta": -5})
            add("humidity_up", "Humidity +5%", "set_humidity", {"_humidity_delta": 5})

    elif domain == "media_player":
        # When Home Assistant publishes supported_features, only display
        # actions that the player advertises. Older integrations that omit the
        # field retain the compatibility fallback.
        try:
            features = int(attrs["supported_features"]) if "supported_features" in attrs else None
        except (TypeError, ValueError):
            features = None
        play_flag = int(MediaPlayerEntityFeature.PLAY)
        pause_flag = int(MediaPlayerEntityFeature.PAUSE)
        if features is None:
            add("play_pause", "Play / pause", "media_play_pause")
            add("next_track", "Next track", "media_next_track")
            add("previous_track", "Previous track", "media_previous_track")
            add("volume_down", "Volume down", "volume_down")
            add("volume_up", "Volume up", "volume_up")
            add("media_on", "Turn on", "turn_on")
            add("media_off", "Turn off", "turn_off")
        else:
            if features & play_flag and features & pause_flag:
                add("play_pause", "Play / pause", "media_play_pause")
            elif features & play_flag:
                add("media_play", "Play / resume", "media_play")
            elif features & pause_flag:
                add("media_pause", "Pause", "media_pause")
            if features & int(MediaPlayerEntityFeature.NEXT_TRACK):
                add("next_track", "Next track", "media_next_track")
            if features & int(MediaPlayerEntityFeature.PREVIOUS_TRACK):
                add("previous_track", "Previous track", "media_previous_track")
            if features & int(MediaPlayerEntityFeature.VOLUME_SET | MediaPlayerEntityFeature.VOLUME_STEP):
                add("volume_down", "Volume down", "volume_down")
                add("volume_up", "Volume up", "volume_up")
            if features & int(MediaPlayerEntityFeature.VOLUME_MUTE) and attrs.get("is_volume_muted") is not None:
                add("volume_mute", "Unmute" if attrs.get("is_volume_muted") else "Mute", "volume_mute", {"is_volume_muted": not bool(attrs.get("is_volume_muted"))})
            if features & int(MediaPlayerEntityFeature.TURN_ON):
                add("media_on", "Turn on", "turn_on")
            if features & int(MediaPlayerEntityFeature.TURN_OFF):
                add("media_off", "Turn off", "turn_off")
            if features & int(MediaPlayerEntityFeature.SHUFFLE_SET) and attrs.get("shuffle") is not None:
                add("shuffle_toggle", "Turn shuffle off" if attrs.get("shuffle") else "Turn shuffle on", "shuffle_set", {"shuffle": not bool(attrs.get("shuffle"))})
            if features & int(MediaPlayerEntityFeature.REPEAT_SET):
                for index, mode in enumerate(("off", "one", "all")):
                    add(f"choose_repeat_{index}", f"Repeat: {mode.title()}", "repeat_set", {"repeat": mode})
            if features & int(MediaPlayerEntityFeature.SELECT_SOUND_MODE):
                sound_modes = attrs.get("sound_mode_list", [])
                if isinstance(sound_modes, list):
                    for index, mode in enumerate(sound_modes[:12]):
                        add(f"choose_sound_mode_{index}", f"Sound: {_short(mode, 42)}", "select_sound_mode", {"sound_mode": mode})
        sources = attrs.get("source_list", [])
        if isinstance(sources, list) and (
            features is None or features & int(MediaPlayerEntityFeature.SELECT_SOURCE)
        ):
            for index, source in enumerate(sources[:24]):
                add(f"choose_source_{index}", f"Source: {_short(source, 42)}", "select_source", {"source": source})

    elif domain in {"select", "input_select"}:
        options = attrs.get("options", [])
        if isinstance(options, list):
            service = "select_option"
            for index, option in enumerate(options):
                add(f"choose_{index}", f"Select: {_short(option, 48)}", service, {"option": option})

    elif domain in {"number", "input_number"}:
        try:
            current = float(state.state)
            step = float(attrs.get("step", 1))
            minimum = float(attrs.get("min", current - 1000000))
            maximum = float(attrs.get("max", current + 1000000))
            service = "set_value"
            add("value_down", f"Decrease by {step:g}", service, {"_value_delta": -step})
            add("value_up", f"Increase by {step:g}", service, {"_value_delta": step})
            add("value_min", "Set minimum", service, {"value": minimum})
            add("value_max", "Set maximum", service, {"value": maximum})
        except (TypeError, ValueError):
            pass
    elif domain == "counter":
        add("increment", "Increment", "increment")
        add("decrement", "Decrement", "decrement")
        add("reset", "Reset", "reset")
    elif domain == "timer":
        add("timer_start", "Start timer", "start")
        add("timer_pause", "Pause timer", "pause")
        add("timer_cancel", "Cancel timer", "cancel")
        add("timer_finish", "Finish timer", "finish")
    elif domain == "vacuum":
        add("vacuum_start", "Start cleaning", "start")
        add("vacuum_pause", "Pause", "pause")
        add("vacuum_stop", "Stop", "stop")
        add("vacuum_home", "Return to base", "return_to_base")
        add("vacuum_spot", "Spot clean", "clean_spot")
    elif domain == "water_heater":
        add("water_on", "Turn on", "turn_on")
        add("water_off", "Turn off", "turn_off")
        modes = attrs.get("operation_list", [])
        if isinstance(modes, list):
            for index, mode in enumerate(modes[:12]):
                add(f"water_mode_{index}", f"Mode: {mode}", "set_operation_mode", {"operation_mode": mode})
    elif domain == "lawn_mower":
        add("mower_start", "Start mowing", "start_mowing")
        add("mower_pause", "Pause mowing", "pause")
        add("mower_dock", "Return to dock", "dock")
    elif domain == "input_datetime":
        # Input requires a separate phone input-screen workflow; report value only.
        pass

    # All other entity domains remain visible as read-only status items.
    return result


def _resolve_action_data(state: Any, action: dict[str, Any]) -> dict[str, Any]:
    """Resolve relative controls against the live state at click time.

    The action URL can remain open on the phone for a while. Computing +/-
    values when rendering it makes repeated presses use stale values, so these
    relative actions are calculated immediately before the service call.
    """
    data = dict(action["data"])
    attrs = state.attributes

    if "_brightness_delta" in data:
        current = attrs.get("brightness", 128)
        try:
            current = int(current)
        except (TypeError, ValueError):
            current = 128
        data["brightness"] = min(255, max(1, current + int(data.pop("_brightness_delta"))))

    if "_percentage_delta" in data:
        try:
            current = int(attrs.get("percentage", 0))
        except (TypeError, ValueError):
            current = 0
        data["percentage"] = min(100, max(0, current + int(data.pop("_percentage_delta"))))

    if "_temperature_delta" in data:
        try:
            current = float(attrs.get("temperature"))
            minimum = float(attrs.get("min_temp", current - 10))
            maximum = float(attrs.get("max_temp", current + 10))
            delta = float(data.pop("_temperature_delta"))
            data["temperature"] = min(maximum, max(minimum, current + delta))
        except (TypeError, ValueError):
            data.pop("_temperature_delta", None)

    if "_value_delta" in data:
        try:
            current = float(state.state)
            minimum = float(attrs.get("min", current - 1_000_000))
            maximum = float(attrs.get("max", current + 1_000_000))
            delta = float(data.pop("_value_delta"))
            data["value"] = min(maximum, max(minimum, current + delta if delta else current))
        except (TypeError, ValueError):
            data.pop("_value_delta", None)

    if "_position_delta" in data:
        try:
            current = float(attrs.get("current_position"))
            delta = float(data.pop("_position_delta"))
            data["position"] = min(100, max(0, current + delta))
        except (TypeError, ValueError):
            data.pop("_position_delta", None)

    if "_humidity_delta" in data:
        try:
            current = float(attrs.get("humidity"))
            delta = float(data.pop("_humidity_delta"))
            minimum = float(attrs.get("min_humidity", 0))
            maximum = float(attrs.get("max_humidity", 100))
            data["humidity"] = min(maximum, max(minimum, current + delta))
        except (TypeError, ValueError):
            data.pop("_humidity_delta", None)

    return data


def _default_action_id(state: Any, tap_behavior: str) -> str | None:
    """Return the one-tap action for an entity, or None to open its controls.

    The default-action mapping is intentionally conservative. In particular,
    locks and climate entities open their controls instead of performing a
    potentially surprising/security-sensitive action on a single key press.
    """
    actions = _available_actions(state)
    if tap_behavior == TAP_BEHAVIOR_MENU:
        return None
    if tap_behavior == TAP_BEHAVIOR_TOGGLE:
        return "toggle" if "toggle" in actions else None

    domain = state.entity_id.split(".", 1)[0]
    direct_actions = {
        "light": "toggle",
        "switch": "toggle",
        "input_boolean": "toggle",
        "fan": "toggle",
        "humidifier": "toggle",
        "siren": "toggle",
        "remote": "toggle",
        "automation": "automation_trigger",
        "scene": "activate",
        "script": "run",
        "button": "press",
        "input_button": "press",
    }
    if domain == "media_player":
        if "play_pause" in actions:
            return "play_pause"
        if state.state == "playing" and "media_pause" in actions:
            return "media_pause"
        if state.state in {"paused", "idle", "off", "standby", "on"} and "media_play" in actions:
            return "media_play"
        return None
    if domain in {"cover", "valve"}:
        # A direct press reverses a settled state. While a cover is moving,
        # Stop is the safest and most predictable one-press action.
        if state.state in {"opening", "closing"}:
            return "stop" if "stop" in actions else None
        if state.state == "closed":
            return "open" if "open" in actions else None
        if state.state == "open":
            return "close" if "close" in actions else None
        return None
    action_id = direct_actions.get(domain)
    return action_id if action_id in actions else None


def _selected_and_state(hass: HomeAssistant, selected: list[str] | set[str], entity_id: str) -> Any | None:
    """Resolve an entity only if it is on the configured allowlist."""
    if entity_id not in selected:
        return None
    return hass.states.get(entity_id)


def _entity_uri(
    endpoint_url: str,
    entity_id: str,
    choice_page: int = 0,
    menu_page: int = 0,
) -> str:
    """Build the detail URL while preserving the user's position in the profile."""
    return _url(
        endpoint_url,
        view="entity",
        entity_id=entity_id,
        choice_page=choice_page,
        menu_page=menu_page,
    )


def _render_menu(
    hass: HomeAssistant,
    selected: list[str],
    page: int,
    endpoint_url: str,
    profile_name: str,
    *,
    tap_behavior: str = DEFAULT_TAP_BEHAVIOR,
    show_controls_entry: bool = DEFAULT_SHOW_CONTROLS_ENTRY,
    notice: str | None = None,
) -> str:
    """Render the ordered profile menu, optionally using one-tap actions.

    Page size is measured in entities. In direct-action mode, a second
    controls row may be shown for each entity; limiting the page to 12 entities
    keeps the resulting TextMenu under Yealink's item limit including refresh,
    navigation, and post-action notice rows.
    """
    rows = _entity_rows(hass, selected)
    split_rows = tap_behavior != TAP_BEHAVIOR_MENU and show_controls_entry
    # Reserve space for previous/next, refresh, and a post-action notice while
    # staying below Yealink's 29 clickable-menu-item limit.
    entity_page_size = 12 if split_rows else ROOT_PAGE_SIZE
    start = page * entity_page_size
    current = rows[start : start + entity_page_size]
    items: list[tuple[str, str]] = []
    if notice:
        items.append((f"Result: {_short(notice, 55)}", _url(endpoint_url, view="menu", page=page)))
    if page > 0:
        items.append(("← Previous page", _url(endpoint_url, view="menu", page=page - 1)))
    for state in current:
        entity_id = state.entity_id
        friendly = _short(_display_name(state), 51)
        state_text = _short(_menu_state_label(state), 28)
        default_action = _default_action_id(state, tap_behavior)
        if default_action:
            target = _url(
                endpoint_url,
                view="action",
                entity_id=entity_id,
                action=default_action,
                choice_page=0,
                menu_page=page,
            )
        else:
            target = _entity_uri(endpoint_url, entity_id, menu_page=page)
        items.append((f"{friendly} — {state_text}", target))
        if split_rows and default_action:
            items.append((f"Controls: {friendly}", _entity_uri(endpoint_url, entity_id, menu_page=page)))
    if start + entity_page_size < len(rows):
        items.append(("Next page →", _url(endpoint_url, view="menu", page=page + 1)))
    if not rows:
        items.append(("No selected entities are currently available", _url(endpoint_url, view="menu", page=page)))
    items.append(("↻ Refresh states", _url(endpoint_url, view="menu", page=page)))
    if not items:
        items.append(("No selected entities are currently available", _url(endpoint_url, view="menu")))
    if len(items) > 29:
        # Final safety cap for unusually large pages or future extra rows.
        # Retain the useful entities first and leave room for pagination.
        items = items[:29]
    return _xml_menu(
        profile_name,
        items,
        base_url=endpoint_url,
        previous=_url(endpoint_url, view="menu", page=max(0, page - 1)),
    )


def _render_domain(hass: HomeAssistant, selected: list[str], domain: str, page: int, menu_page: int, base_url: str) -> str:
    """Render a paginated list of selected entities in one domain."""
    rows = [state for state in _entity_rows(hass, selected) if state.entity_id.split(".", 1)[0] == domain]
    start = page * ENTITY_PAGE_SIZE
    current = rows[start : start + ENTITY_PAGE_SIZE]
    items: list[tuple[str, str]] = []
    if page > 0:
        items.append(("← Previous entities", _url(base_url, view="domain", domain=domain, page=page - 1, menu_page=menu_page)))
    for state in current:
        friendly = _short(_display_name(state), 55)
        state_text = _short(state.state, 18)
        items.append((f"{friendly} — {state_text}", _entity_uri(base_url, state.entity_id)))
    if start + ENTITY_PAGE_SIZE < len(rows):
        items.append(("Next entities →", _url(base_url, view="domain", domain=domain, page=page + 1, menu_page=menu_page)))
    if not rows:
        items.append(("No selected entities in this category", _url(base_url, view="menu", page=menu_page)))
    return _xml_menu(_domain_label(domain), items, base_url=base_url, previous=_url(base_url, view="menu", page=menu_page))


def _render_entity(
    hass: HomeAssistant,
    selected: list[str],
    entity_id: str,
    choice_page: int = 0,
    *,
    base_url: str,
    menu_page: int = 0,
    notice: str | None = None,
) -> str:
    """Render entity status, available controls, and choice pagination."""
    state = _selected_and_state(hass, selected, entity_id)
    if state is None:
        return _xml_menu("Entity unavailable", [("Return to menu", _url(base_url, view="menu", page=menu_page))], base_url=base_url, previous=_url(base_url, view="menu", page=menu_page))

    actions = _available_actions(state)
    # Potentially long option lists must be paginated instead of being allowed
    # to crowd important controls off the T42S screen.
    choice_ids = [
        key
        for key in actions
        if key.startswith(("choose_", "hvac_mode_", "water_mode_"))
    ]
    choice_start = choice_page * CHOICE_PAGE_SIZE
    choice_id_set = set(choice_ids)
    base_actions = {
        key: action for key, action in actions.items() if key not in choice_id_set
    }

    items: list[tuple[str, str]] = []
    if notice:
        items.append((f"Last action: {_short(notice, 55)}", _entity_uri(base_url, entity_id, choice_page, menu_page)))
    items.append((f"State: {_short(state.state, 42)}", _entity_uri(base_url, entity_id, choice_page, menu_page)))
    for key in ("unit_of_measurement", "current_temperature", "temperature", "humidity", "battery_level", "percentage", "hvac_mode", "source", "friendly_name"):
        value = state.attributes.get(key)
        if value is None or key == "friendly_name":
            continue
        label = f"{key.replace('_', ' ').title()}: {_short(value, 46)}"
        items.append((label, _entity_uri(base_url, entity_id, choice_page, menu_page)))
        # Reserve display space for controls and both pagination directions.
        if len(items) >= 3:
            break

    # Keep basic controls on screen, then page through select/input_select choices.
    for action_id, action in base_actions.items():
        items.append((action["label"], _url(base_url, view="action", entity_id=entity_id, action=action_id, choice_page=choice_page, menu_page=menu_page)))
    for action_id in choice_ids[choice_start : choice_start + CHOICE_PAGE_SIZE]:
        items.append((actions[action_id]["label"], _url(base_url, view="action", entity_id=entity_id, action=action_id, choice_page=choice_page, menu_page=menu_page)))
    if choice_start > 0:
        items.append(("← Previous choices", _entity_uri(base_url, entity_id, choice_page - 1, menu_page)))
    if choice_start + CHOICE_PAGE_SIZE < len(choice_ids):
        items.append(("More choices →", _entity_uri(base_url, entity_id, choice_page + 1, menu_page)))

    return _xml_menu(_short(_display_name(state), 60), items, base_url=base_url, previous=_url(base_url, view="menu", page=menu_page))


def _error_xml(message: str, endpoint_url: str, profile_name: str = "Home Assistant") -> str:
    """Render an error in a phone-friendly XML menu."""
    return _xml_menu(
        profile_name,
        [(message, _url(endpoint_url, view="menu"))],
        base_url=endpoint_url,
        previous=_url(endpoint_url, view="menu"),
    )


def _entry_profile_id(entry: ConfigEntry) -> str:
    """Return a stable profile slug; old single-profile entries become default."""
    return str(entry.data.get(CONF_PROFILE_ID) or "default")


class YealinkXmlView(HomeAssistantView):
    """Serve the legacy root endpoint and support ?profile=slug selection."""

    url = VIEW_PATH
    name = "api:yealink_xml"
    requires_auth = False

    async def get(self, request: web.Request) -> web.Response:
        """Handle a profile request on the backwards-compatible endpoint."""
        return await self._handle(request, request.query.get("profile"))

    async def _handle(self, request: web.Request, requested_profile: str | None) -> web.Response:
        """Select a profile, authenticate it, and serve XML or an allowed action."""
        hass: HomeAssistant = request.app[KEY_HASS]
        entries = hass.config_entries.async_entries(DOMAIN)
        entry: ConfigEntry | None = None

        if requested_profile:
            entry = next((item for item in entries if _entry_profile_id(item) == requested_profile), None)
            if entry is None:
                return web.Response(status=404, text="Unknown Yealink phone profile")
        else:
            # Existing phone URLs without a profile keep working for legacy/default
            # profiles. Otherwise, a single configured profile is unambiguous.
            defaults = [item for item in entries if _entry_profile_id(item) == "default"]
            if len(defaults) == 1:
                entry = defaults[0]
            elif len(entries) == 1:
                entry = entries[0]
            elif not entries:
                return web.Response(status=404, text="Yealink XML Browser is not configured")
            else:
                return web.Response(
                    status=400,
                    text="Specify the phone profile in the URL, e.g. /api/yealink_xml/bedroom?view=menu",
                )

        if entry is None:
            return web.Response(status=404, text="Yealink XML Browser integration is not configured")
        # The initial XML URL is authenticated with Basic Auth. Some phone
        # firmware does not re-send that header on each MenuItem URI, so links
        # emitted by this integration also carry an HMAC bound to the full
        # request path/query. This cannot be changed to another entity/action.
        # The signed-link check is cheap, so try it before the password hash.
        if not (
            _verify_signed_request(request, entry)
            or await _async_verify_basic_auth(hass, request, entry)
        ):
            return web.Response(
                status=401,
                text="XML Browser authentication required",
                headers={"WWW-Authenticate": 'Basic realm="Yealink XML Browser", charset="UTF-8"'},
            )

        selected = list(entry.options.get(CONF_ENTITIES, []))
        origin_url = str(entry.options.get(CONF_BASE_URL, "http://homeassistant.local:8123")).rstrip("/")
        profile_id = _entry_profile_id(entry)
        # Menus always link back to this profile-specific path. A room's phone can
        # therefore never accidentally land in another room's allowlist.
        endpoint_url = f"{origin_url}{VIEW_PATH}/{quote(profile_id, safe='')}"
        profile_name = str(entry.options.get(CONF_PROFILE_NAME, entry.title or profile_id))
        view = request.query.get("view", "menu")
        page = _int_query(request, "page")
        menu_page = _int_query(request, "menu_page")
        choice_page = _int_query(request, "choice_page")

        try:
            tap_behavior = str(entry.options.get(CONF_TAP_BEHAVIOR, DEFAULT_TAP_BEHAVIOR))
            after_action = str(entry.options.get(CONF_AFTER_ACTION, DEFAULT_AFTER_ACTION))
            show_controls_entry = bool(entry.options.get(CONF_SHOW_CONTROLS_ENTRY, DEFAULT_SHOW_CONTROLS_ENTRY))

            if view == "menu":
                xml = _render_menu(
                    hass,
                    selected,
                    page,
                    endpoint_url,
                    profile_name,
                    tap_behavior=tap_behavior,
                    show_controls_entry=show_controls_entry,
                )
            elif view == "domain":
                # Legacy category URLs remain navigable after the upgrade.
                domain = request.query.get("domain", "")
                if not domain or "." in domain or not domain.replace("_", "").isalnum():
                    xml = _error_xml("Invalid category", endpoint_url, profile_name)
                else:
                    xml = _render_domain(hass, selected, domain, page, menu_page, endpoint_url)
            elif view == "entity":
                entity_id = request.query.get("entity_id", "")
                if _selected_and_state(hass, selected, entity_id) is None:
                    xml = _error_xml("Entity is not selected or unavailable", endpoint_url, profile_name)
                else:
                    xml = _render_entity(
                        hass, selected, entity_id, choice_page,
                        base_url=endpoint_url, menu_page=menu_page,
                    )
            elif view == "action":
                entity_id = request.query.get("entity_id", "")
                action_id = request.query.get("action", "")
                state = _selected_and_state(hass, selected, entity_id)
                if state is None:
                    xml = _error_xml("Entity is not selected or unavailable", endpoint_url, profile_name)
                else:
                    action = _available_actions(state).get(action_id)
                    if action is None:
                        xml = _error_xml("Action is not allowed for this entity", endpoint_url, profile_name)
                    else:
                        service_data = {"entity_id": entity_id, **_resolve_action_data(state, action)}
                        previous_snapshot = _state_snapshot(state)
                        try:
                            await hass.services.async_call(
                                action["domain"],
                                action["service"],
                                service_data,
                                blocking=True,
                            )
                            # Service completion doesn't always mean the entity has
                            # published its new state yet (especially for slower LAN
                            # or cloud devices). Wait only when the selected entity is
                            # expected to change, and return immediately on an update.
                            state_wait = _configured_state_wait(
                                entry.options.get(CONF_STATE_WAIT, DEFAULT_STATE_WAIT)
                            )
                            if state_wait and _should_wait_for_state_update(state, action_id):
                                updated = await _wait_for_entity_update(
                                    hass, entity_id, previous_snapshot, state_wait
                                )
                                if not updated:
                                    _LOGGER.debug(
                                        "Timed out waiting %.1fs for %s to report after %s",
                                        state_wait,
                                        entity_id,
                                        action_id,
                                    )
                            if after_action == AFTER_ACTION_ENTITY:
                                xml = _render_entity(
                                    hass,
                                    selected,
                                    entity_id,
                                    choice_page,
                                    base_url=endpoint_url,
                                    menu_page=menu_page,
                                    notice=action["label"],
                                )
                            else:
                                xml = _render_menu(
                                    hass,
                                    selected,
                                    menu_page,
                                    endpoint_url,
                                    profile_name,
                                    tap_behavior=tap_behavior,
                                    show_controls_entry=show_controls_entry,
                                )
                        except Exception:  # noqa: BLE001 - show failure on the phone
                            _LOGGER.exception("Yealink action failed for %s (%s)", entity_id, action_id)
                            if after_action == AFTER_ACTION_ENTITY:
                                xml = _render_entity(
                                    hass,
                                    selected,
                                    entity_id,
                                    choice_page,
                                    base_url=endpoint_url,
                                    menu_page=menu_page,
                                    notice="Action failed; check Home Assistant logs",
                                )
                            else:
                                xml = _render_menu(
                                    hass,
                                    selected,
                                    menu_page,
                                    endpoint_url,
                                    profile_name,
                                    tap_behavior=tap_behavior,
                                    show_controls_entry=show_controls_entry,
                                    notice="Action failed; check Home Assistant logs",
                                )
            else:
                xml = _error_xml("Unknown menu request", endpoint_url, profile_name)
        except Exception:  # noqa: BLE001 - don't return tracebacks to the phone
            _LOGGER.exception("Could not build Yealink XML response for profile %s", profile_id)
            xml = _error_xml("Could not build menu; check Home Assistant logs", endpoint_url, profile_name)

        # Sign all child links after rendering. The initial URL still requires
        # Basic Auth; follow-up requests can safely work on phones that do not
        # resend Authorization for URI links.
        xml = _sign_xml_links(xml, entry)
        return web.Response(
            text=xml,
            content_type="text/xml",
            charset="UTF-8",
            headers={"Cache-Control": "no-store, max-age=0", "Pragma": "no-cache"},
        )


class YealinkXmlProfileView(YealinkXmlView):
    """Serve /api/yealink_xml/{profile} so each phone has a dedicated URL."""

    url = f"{VIEW_PATH}/{{profile}}"
    name = "api:yealink_xml:profile"

    async def get(self, request: web.Request, profile: str) -> web.Response:
        """Handle a request for the profile embedded in the URL path."""
        return await self._handle(request, profile)
