"""Config and options flows for Yealink XML Browser phone profiles."""

from __future__ import annotations

import hashlib
import re
import secrets
from typing import Any
from urllib.parse import quote, urlsplit, urlencode

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.components import persistent_notification
from homeassistant.helpers import selector
from homeassistant.helpers.network import NoURLAvailableError, get_url

from .const import (
    CONF_BASE_URL,
    CONF_ENTITIES,
    CONF_TAP_BEHAVIOR,
    CONF_AFTER_ACTION,
    CONF_SHOW_CONTROLS_ENTRY,
    CONF_STATE_WAIT,
    TAP_BEHAVIOR_MENU,
    TAP_BEHAVIOR_DEFAULT,
    TAP_BEHAVIOR_TOGGLE,
    AFTER_ACTION_MENU,
    AFTER_ACTION_ENTITY,
    DEFAULT_TAP_BEHAVIOR,
    DEFAULT_AFTER_ACTION,
    DEFAULT_SHOW_CONTROLS_ENTRY,
    DEFAULT_STATE_WAIT,
    DEFAULT_PHONE_ACTIONS,
    PHONE_ACTIONS,
    STATE_WAIT_OPTIONS,
    CONF_NEW_PASSWORD,
    CONF_NEW_USERNAME,
    CONF_PASSWORD_HASH,
    CONF_PASSWORD_SALT,
    CONF_PHONE_ACTIONS,
    CONF_PHONE_PASSWORD,
    CONF_PHONE_URL,
    CONF_PHONE_USERNAME,
    CONF_PHONE_VERIFY_SSL,
    CONF_PROFILE_ID,
    CONF_PROFILE_NAME,
    CONF_USERNAME,
    DOMAIN,
    VIEW_PATH,
)

_PROFILE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")


def _password_hash(password: str, salt: str) -> str:
    """Hash a phone password before storing it in the config entry."""
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt), 150_000
    ).hex()


def _entry_profile_id(entry: config_entries.ConfigEntry) -> str:
    """Return a stable profile ID, including for entries created by v0.1."""
    profile_id = entry.data.get(CONF_PROFILE_ID)
    if profile_id:
        return str(profile_id)
    # The first prototype allowed exactly one entry with unique_id == DOMAIN.
    return "default"


def _valid_base_url(value: str) -> bool:
    """Require an HTTP(S) origin so links can be absolute phone URLs."""
    try:
        parsed = urlsplit(value.strip())
        if (
            len(value.strip()) > 200
            or parsed.scheme not in {"http", "https"}
            or not parsed.hostname
        ):
            return False
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            return False
        if parsed.path not in {"", "/"}:
            return False
        if parsed.port is not None and not (1 <= parsed.port <= 65535):
            return False
        return True
    except ValueError:
        return False


def _phone_url(base_url: str, profile_id: str) -> str:
    """Build the exact URL to paste into the Yealink XML Browser field."""
    return f"{base_url.rstrip('/')}{VIEW_PATH}/{quote(profile_id, safe='')}?{urlencode({'view': 'menu'})}"


def _preview_base_url(value: Any) -> str:
    """Return a useful preview before the user has entered their own address."""
    text = str(value or "").strip().rstrip("/")
    if _valid_base_url(text):
        return text
    return "http://<YOUR-HA-IP>:8123"


def _suggested_ha_url(hass: Any) -> str:
    """Suggest HA's configured internal URL or its discovered local address."""
    try:
        return get_url(
            hass,
            allow_external=False,
            allow_cloud=False,
            prefer_external=False,
        ).rstrip("/")
    except NoURLAvailableError:
        return ""


def _embedded_auth_url_template(base_url: str, profile_id: str, username: str) -> str:
    """Build a credentials-in-URL example without storing or displaying the password."""
    parsed = urlsplit(base_url)
    safe_username = ("<USERNAME>" if not username or username == "<USERNAME>" else quote(username, safe=""))
    query = urlencode({"view": "menu"})
    return (
        f"{parsed.scheme}://{safe_username}:<YOUR_PASSWORD>@{parsed.netloc}"
        f"{VIEW_PATH}/{quote(profile_id, safe='')}?{query}"
    )


def _setup_notification_message(
    base_url: str,
    profile_id: str,
    username: str,
    phone_url: str | None = None,
) -> str:
    """Create first-time phone setup instructions with the generated URL."""
    xml_browser_url = _phone_url(base_url, profile_id)
    embedded_url = _embedded_auth_url_template(base_url, profile_id, username)
    message = (
        "Your Yealink XML Browser profile is configured. Follow these steps on the phone.\n\n"
        "**1. XML Browser URL**\n\n"
        f"Copy this URL into the phone's XML Browser / remote menu URL field:\n\n`{xml_browser_url}`\n\n"
        "**2. Authentication**\n\n"
        f"Username: `{username}`\n\n"
        "Password: the password you entered while creating this profile. If the phone has separate "
        "XML Browser username/password fields, enter the username and password there.\n\n"
        "**If your phone only has one URL field**\n\n"
        "Some phones accept credentials directly in the URL. Use this template, replacing "
        "`<YOUR_PASSWORD>` with the password you chose (remove the angle brackets):\n\n"
        f"`{embedded_url}`\n\n"
        "For credentials-in-URL, a letters-and-numbers password is easiest; reserved URL characters need "
        "percent-encoding. Prefer separate authentication fields when available because a URL containing "
        "credentials may be saved in phone configuration or logs.\n\n"
        "**Important:** the URL must use the Home Assistant address reachable from the phone, normally "
        "the server's LAN IP and port `8123`. Do not expose this endpoint to the internet; plain HTTP "
        "does not encrypt credentials. The URL is also shown on this profile's **Configure** screen; save there to refresh this notification."
    )
    if phone_url:
        message += (
            "\n\n**Home Assistant phone controls**\n\n"
            "This profile also has Yealink phone action buttons in Home Assistant. "
            "On the phone, allow Action URI requests from the Home Assistant IP "
            "(Features → Remote Control → Action URI Allow IP List). DND buttons "
            "also require DND to be enabled (features.dnd.allow=1). To receive pushed "
            "notifications, add the same Home Assistant IP under Features → Remote Control "
            "→ Push XML Server IP Address."
        )
    return message


def _create_setup_notification(
    hass: Any,
    base_url: str,
    profile_id: str,
    username: str,
    phone_url: str | None = None,
) -> None:
    """Show the exact URL and phone setup instructions after saving a profile."""
    persistent_notification.async_create(
        hass,
        _setup_notification_message(base_url, profile_id, username, phone_url),
        title=f"Yealink XML Browser: connect {profile_id}",
        notification_id=f"yealink_xml_setup_{profile_id}",
    )


USERNAME_SELECTOR = selector.TextSelector(
    selector.TextSelectorConfig(
        type=selector.TextSelectorType.TEXT, autocomplete="username"
    )
)
PASSWORD_SELECTOR = selector.TextSelector(
    selector.TextSelectorConfig(
        type=selector.TextSelectorType.PASSWORD,
        autocomplete="new-password",
    )
)
PROFILE_NAME_SELECTOR = selector.TextSelector(
    selector.TextSelectorConfig(type=selector.TextSelectorType.TEXT)
)
PROFILE_ID_SELECTOR = selector.TextSelector(
    selector.TextSelectorConfig(type=selector.TextSelectorType.TEXT)
)
ENTITY_SELECTOR = selector.EntitySelector(
    selector.EntitySelectorConfig(multiple=True, reorder=True)
)
TAP_BEHAVIOR_SELECTOR = selector.SelectSelector(
    selector.SelectSelectorConfig(
        options=[
            {"label": "Run default action on select", "value": TAP_BEHAVIOR_DEFAULT},
            {"label": "Toggle where supported", "value": TAP_BEHAVIOR_TOGGLE},
            {"label": "Open action menu", "value": TAP_BEHAVIOR_MENU},
        ],
        mode=selector.SelectSelectorMode.DROPDOWN,
    )
)
AFTER_ACTION_SELECTOR = selector.SelectSelector(
    selector.SelectSelectorConfig(
        options=[
            {"label": "Return to phone main menu", "value": AFTER_ACTION_MENU},
            {"label": "Stay on entity controls", "value": AFTER_ACTION_ENTITY},
        ],
        mode=selector.SelectSelectorMode.DROPDOWN,
    )
)
SHOW_CONTROLS_SELECTOR = selector.BooleanSelector()
STATE_WAIT_SELECTOR = selector.SelectSelector(
    selector.SelectSelectorConfig(
        options=[
            {"label": "No wait (fastest)", "value": "0"},
            {"label": "Up to 0.5 seconds", "value": "0.5"},
            {"label": "Up to 1 second", "value": "1"},
            {"label": "Up to 1.5 seconds", "value": "1.5"},
            {"label": "Up to 2 seconds", "value": "2"},
            {"label": "Up to 3 seconds", "value": "3"},
            {"label": "Up to 4 seconds", "value": "4"},
            {"label": "Up to 5 seconds (slow devices)", "value": "5"},
        ],
        mode=selector.SelectSelectorMode.DROPDOWN,
    )
)
URL_SELECTOR = selector.TextSelector(
    selector.TextSelectorConfig(type=selector.TextSelectorType.URL, autocomplete="url")
)
PHONE_ACTION_SELECTOR = selector.SelectSelector(
    selector.SelectSelectorConfig(
        options=[
            {"label": label, "value": action_id}
            for action_id, (label, _key) in PHONE_ACTIONS.items()
        ],
        multiple=True,
        mode=selector.SelectSelectorMode.LIST,
    )
)


class YealinkXmlConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Set up one independent Yealink phone profile."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        """Create a named phone profile with its own allowlist and credentials."""
        errors: dict[str, str] = {}
        if user_input is not None:
            profile_name = str(user_input.get(CONF_PROFILE_NAME, "")).strip()
            profile_id = str(user_input.get(CONF_PROFILE_ID, "")).strip().lower()
            username = str(user_input.get(CONF_USERNAME, "")).strip()
            password = str(user_input.get("password", ""))
            entities = list(dict.fromkeys(user_input.get(CONF_ENTITIES, [])))
            base_url = str(user_input.get(CONF_BASE_URL, "")).strip().rstrip("/")
            tap_behavior = str(user_input.get(CONF_TAP_BEHAVIOR, DEFAULT_TAP_BEHAVIOR))
            after_action = str(user_input.get(CONF_AFTER_ACTION, DEFAULT_AFTER_ACTION))
            show_controls_entry = bool(user_input.get(CONF_SHOW_CONTROLS_ENTRY, DEFAULT_SHOW_CONTROLS_ENTRY))
            state_wait = str(user_input.get(CONF_STATE_WAIT, str(DEFAULT_STATE_WAIT)))
            phone_url = str(user_input.get(CONF_PHONE_URL, "")).strip().rstrip("/")
            phone_username = str(user_input.get(CONF_PHONE_USERNAME, "")).strip()
            phone_password = str(user_input.get(CONF_PHONE_PASSWORD, ""))
            phone_verify_ssl = bool(user_input.get(CONF_PHONE_VERIFY_SSL, True))
            phone_actions = list(dict.fromkeys(user_input.get(CONF_PHONE_ACTIONS, DEFAULT_PHONE_ACTIONS)))

            if not profile_name or len(profile_name) > 48:
                errors[CONF_PROFILE_NAME] = "invalid_profile_name"
            elif not _PROFILE_ID_RE.fullmatch(profile_id):
                errors[CONF_PROFILE_ID] = "invalid_profile_id"
            elif any(_entry_profile_id(entry) == profile_id for entry in self.hass.config_entries.async_entries(DOMAIN)):
                errors[CONF_PROFILE_ID] = "duplicate_profile"
            elif not _valid_base_url(base_url):
                errors["base"] = "invalid_base_url"
            elif not username or len(username) > 15 or ":" in username or any(
                ord(char) < 32 for char in username
            ):
                errors[CONF_USERNAME] = "invalid_username"
            elif not password or len(password) < 8 or len(password) > 15:
                errors["password"] = "invalid_password"
            elif not entities:
                errors[CONF_ENTITIES] = "select_entities"
            elif phone_url and not _valid_base_url(phone_url):
                errors[CONF_PHONE_URL] = "invalid_phone_url"
            elif not (
                bool(phone_url) == bool(phone_username) == bool(phone_password)
            ):
                errors["base"] = "phone_credentials_required"
            elif phone_username and (
                len(phone_username) > 64
                or ":" in phone_username
                or any(ord(char) < 32 for char in phone_username)
            ):
                errors[CONF_PHONE_USERNAME] = "invalid_phone_username"
            elif phone_password and (
                len(phone_password) > 128 or any(ord(char) < 32 for char in phone_password)
            ):
                errors[CONF_PHONE_PASSWORD] = "invalid_phone_password"
            elif any(action not in PHONE_ACTIONS for action in phone_actions):
                errors[CONF_PHONE_ACTIONS] = "invalid_phone_actions"
            elif tap_behavior not in {TAP_BEHAVIOR_MENU, TAP_BEHAVIOR_DEFAULT, TAP_BEHAVIOR_TOGGLE}:
                errors[CONF_TAP_BEHAVIOR] = "invalid_tap_behavior"
            elif after_action not in {AFTER_ACTION_MENU, AFTER_ACTION_ENTITY}:
                errors[CONF_AFTER_ACTION] = "invalid_after_action"
            elif state_wait not in STATE_WAIT_OPTIONS:
                errors[CONF_STATE_WAIT] = "invalid_state_wait"
            else:
                await self.async_set_unique_id(f"{DOMAIN}:{profile_id}")
                self._abort_if_unique_id_configured()
                salt = secrets.token_hex(16)
                _create_setup_notification(
                    self.hass, base_url, profile_id, username, phone_url or None
                )
                options = {
                    CONF_PROFILE_NAME: profile_name,
                    CONF_ENTITIES: entities,
                    CONF_BASE_URL: base_url,
                    CONF_TAP_BEHAVIOR: tap_behavior,
                    CONF_AFTER_ACTION: after_action,
                    CONF_SHOW_CONTROLS_ENTRY: show_controls_entry,
                    CONF_STATE_WAIT: state_wait,
                    CONF_PHONE_URL: phone_url,
                    CONF_PHONE_VERIFY_SSL: phone_verify_ssl,
                    CONF_PHONE_ACTIONS: phone_actions,
                }
                if phone_url:
                    options[CONF_PHONE_USERNAME] = phone_username
                    options[CONF_PHONE_PASSWORD] = phone_password
                return self.async_create_entry(
                    title=profile_name,
                    data={
                        CONF_PROFILE_ID: profile_id,
                        CONF_USERNAME: username,
                        CONF_PASSWORD_SALT: salt,
                        CONF_PASSWORD_HASH: await self.hass.async_add_executor_job(_password_hash, password, salt),
                    },
                    options=options,
                )

        suggested_base_url = _suggested_ha_url(self.hass)
        schema = vol.Schema(
            {
                vol.Required(CONF_PROFILE_NAME, default="Phone"): PROFILE_NAME_SELECTOR,
                vol.Required(CONF_PROFILE_ID, default="phone"): PROFILE_ID_SELECTOR,
                vol.Required(CONF_USERNAME): USERNAME_SELECTOR,
                vol.Required("password"): PASSWORD_SELECTOR,
                vol.Required(CONF_BASE_URL, default=suggested_base_url): URL_SELECTOR,
                vol.Required(CONF_ENTITIES, default=[]): ENTITY_SELECTOR,
                vol.Required(CONF_TAP_BEHAVIOR, default=DEFAULT_TAP_BEHAVIOR): TAP_BEHAVIOR_SELECTOR,
                vol.Required(CONF_AFTER_ACTION, default=DEFAULT_AFTER_ACTION): AFTER_ACTION_SELECTOR,
                vol.Required(CONF_SHOW_CONTROLS_ENTRY, default=DEFAULT_SHOW_CONTROLS_ENTRY): SHOW_CONTROLS_SELECTOR,
                vol.Required(CONF_STATE_WAIT, default=str(DEFAULT_STATE_WAIT)): STATE_WAIT_SELECTOR,
                vol.Optional(CONF_PHONE_URL, default=""): URL_SELECTOR,
                vol.Optional(CONF_PHONE_USERNAME): USERNAME_SELECTOR,
                vol.Optional(CONF_PHONE_PASSWORD): PASSWORD_SELECTOR,
                vol.Required(CONF_PHONE_VERIFY_SSL, default=True): SHOW_CONTROLS_SELECTOR,
                vol.Required(CONF_PHONE_ACTIONS, default=list(DEFAULT_PHONE_ACTIONS)): PHONE_ACTION_SELECTOR,
            }
        )
        preview_base = _preview_base_url(
            (user_input or {}).get(CONF_BASE_URL, suggested_base_url)
        )
        preview_id = str((user_input or {}).get(CONF_PROFILE_ID, "phone")).strip().lower()
        if not _PROFILE_ID_RE.fullmatch(preview_id):
            preview_id = "phone"
        preview_user = str((user_input or {}).get(CONF_USERNAME, "<USERNAME>")).strip() or "<USERNAME>"
        return self.async_show_form(
            step_id="user",
            data_schema=self.add_suggested_values_to_schema(schema, user_input or {}),
            description_placeholders={
                "phone_url": _phone_url(preview_base, preview_id),
                "embedded_url_template": _embedded_auth_url_template(preview_base, preview_id, preview_user),
                "suggested_base_url": suggested_base_url or "",
            },
            errors=errors,
        )

    @staticmethod
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> YealinkXmlOptionsFlow:
        """Create the options flow (the entry is supplied by Home Assistant)."""
        return YealinkXmlOptionsFlow()


class YealinkXmlOptionsFlow(config_entries.OptionsFlow):
    """Edit an individual phone profile, its ordered entities, and credentials."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        """Edit entity selection/order and optionally rotate phone credentials."""
        errors: dict[str, str] = {}
        if user_input is not None:
            current_options = dict(self.config_entry.options)
            profile_name = str(user_input.get(CONF_PROFILE_NAME, self.config_entry.title)).strip()
            entities = list(dict.fromkeys(user_input.get(CONF_ENTITIES, [])))
            base_url = str(
                user_input.get(CONF_BASE_URL, current_options.get(CONF_BASE_URL, ""))
            ).strip().rstrip("/")
            tap_behavior = str(user_input.get(CONF_TAP_BEHAVIOR, DEFAULT_TAP_BEHAVIOR))
            after_action = str(user_input.get(CONF_AFTER_ACTION, DEFAULT_AFTER_ACTION))
            show_controls_entry = bool(user_input.get(CONF_SHOW_CONTROLS_ENTRY, DEFAULT_SHOW_CONTROLS_ENTRY))
            state_wait = str(user_input.get(CONF_STATE_WAIT, str(DEFAULT_STATE_WAIT)))
            new_username = str(user_input.get(CONF_NEW_USERNAME, "")).strip()
            new_password = str(user_input.get(CONF_NEW_PASSWORD, ""))
            current_phone_url = str(current_options.get(CONF_PHONE_URL, ""))
            current_phone_username = str(current_options.get(CONF_PHONE_USERNAME, ""))
            current_phone_password = str(current_options.get(CONF_PHONE_PASSWORD, ""))
            phone_url = str(user_input.get(CONF_PHONE_URL, current_phone_url)).strip().rstrip("/")
            phone_username = str(
                user_input.get(CONF_PHONE_USERNAME, current_phone_username)
            ).strip()
            new_phone_password = str(user_input.get(CONF_PHONE_PASSWORD, ""))
            phone_password = new_phone_password or current_phone_password
            phone_verify_ssl = bool(
                user_input.get(
                    CONF_PHONE_VERIFY_SSL,
                    current_options.get(CONF_PHONE_VERIFY_SSL, True),
                )
            )
            phone_actions = list(
                dict.fromkeys(
                    user_input.get(
                        CONF_PHONE_ACTIONS,
                        current_options.get(CONF_PHONE_ACTIONS, DEFAULT_PHONE_ACTIONS),
                    )
                )
            )

            if not profile_name or len(profile_name) > 48:
                errors[CONF_PROFILE_NAME] = "invalid_profile_name"
            elif not _valid_base_url(base_url):
                errors["base"] = "invalid_base_url"
            elif not entities:
                errors[CONF_ENTITIES] = "select_entities"
            elif phone_url and not _valid_base_url(phone_url):
                errors[CONF_PHONE_URL] = "invalid_phone_url"
            elif phone_url and (not phone_username or not phone_password):
                errors["base"] = "phone_credentials_required"
            elif phone_url and phone_username != current_phone_username and not new_phone_password:
                errors["base"] = "phone_password_required_for_username_change"
            elif phone_username and (
                len(phone_username) > 64
                or ":" in phone_username
                or any(ord(char) < 32 for char in phone_username)
            ):
                errors[CONF_PHONE_USERNAME] = "invalid_phone_username"
            elif new_phone_password and (
                len(new_phone_password) > 128
                or any(ord(char) < 32 for char in new_phone_password)
            ):
                errors[CONF_PHONE_PASSWORD] = "invalid_phone_password"
            elif any(action not in PHONE_ACTIONS for action in phone_actions):
                errors[CONF_PHONE_ACTIONS] = "invalid_phone_actions"
            elif tap_behavior not in {TAP_BEHAVIOR_MENU, TAP_BEHAVIOR_DEFAULT, TAP_BEHAVIOR_TOGGLE}:
                errors[CONF_TAP_BEHAVIOR] = "invalid_tap_behavior"
            elif after_action not in {AFTER_ACTION_MENU, AFTER_ACTION_ENTITY}:
                errors[CONF_AFTER_ACTION] = "invalid_after_action"
            elif state_wait not in STATE_WAIT_OPTIONS:
                errors[CONF_STATE_WAIT] = "invalid_state_wait"
            elif bool(new_username) != bool(new_password):
                errors["base"] = "credentials_together"
            elif new_username and (
                len(new_username) > 15
                or ":" in new_username
                or any(ord(char) < 32 for char in new_username)
            ):
                errors[CONF_NEW_USERNAME] = "invalid_username"
            elif new_password and (len(new_password) < 8 or len(new_password) > 15):
                errors[CONF_NEW_PASSWORD] = "invalid_password"
            else:
                if profile_name != self.config_entry.title:
                    self.hass.config_entries.async_update_entry(
                        self.config_entry, title=profile_name
                    )
                if new_username and new_password:
                    salt = secrets.token_hex(16)
                    data = dict(self.config_entry.data)
                    data.update(
                        {
                            CONF_USERNAME: new_username,
                            CONF_PASSWORD_SALT: salt,
                            CONF_PASSWORD_HASH: await self.hass.async_add_executor_job(_password_hash, new_password, salt),
                        }
                    )
                    self.hass.config_entries.async_update_entry(
                        self.config_entry, data=data
                    )
                saved_username = new_username or str(self.config_entry.data.get(CONF_USERNAME, ""))
                _create_setup_notification(
                    self.hass,
                    base_url,
                    _entry_profile_id(self.config_entry),
                    saved_username,
                    phone_url or None,
                )
                options = {
                    CONF_PROFILE_NAME: profile_name,
                    CONF_ENTITIES: entities,
                    CONF_BASE_URL: base_url,
                    CONF_TAP_BEHAVIOR: tap_behavior,
                    CONF_AFTER_ACTION: after_action,
                    CONF_SHOW_CONTROLS_ENTRY: show_controls_entry,
                    CONF_STATE_WAIT: state_wait,
                    CONF_PHONE_URL: phone_url,
                    CONF_PHONE_VERIFY_SSL: phone_verify_ssl,
                    CONF_PHONE_ACTIONS: phone_actions,
                }
                if phone_url:
                    options[CONF_PHONE_USERNAME] = phone_username
                    options[CONF_PHONE_PASSWORD] = phone_password
                return self.async_create_entry(
                    title="",
                    data=options,
                )

        current_options = dict(self.config_entry.options)
        suggested_base_url = _suggested_ha_url(self.hass)
        suggested: dict[str, Any] = {
            CONF_PROFILE_NAME: current_options.get(CONF_PROFILE_NAME, self.config_entry.title),
            CONF_BASE_URL: current_options.get(CONF_BASE_URL, suggested_base_url),
            CONF_ENTITIES: current_options.get(CONF_ENTITIES, []),
            CONF_TAP_BEHAVIOR: current_options.get(CONF_TAP_BEHAVIOR, DEFAULT_TAP_BEHAVIOR),
            CONF_AFTER_ACTION: current_options.get(CONF_AFTER_ACTION, DEFAULT_AFTER_ACTION),
            CONF_SHOW_CONTROLS_ENTRY: current_options.get(CONF_SHOW_CONTROLS_ENTRY, DEFAULT_SHOW_CONTROLS_ENTRY),
            CONF_STATE_WAIT: str(current_options.get(CONF_STATE_WAIT, DEFAULT_STATE_WAIT)),
            CONF_PHONE_URL: current_options.get(CONF_PHONE_URL, ""),
            CONF_PHONE_USERNAME: current_options.get(CONF_PHONE_USERNAME, ""),
            CONF_PHONE_VERIFY_SSL: current_options.get(CONF_PHONE_VERIFY_SSL, True),
            CONF_PHONE_ACTIONS: current_options.get(CONF_PHONE_ACTIONS, list(DEFAULT_PHONE_ACTIONS)),
        }
        if user_input:
            suggested.update(user_input)

        schema = vol.Schema(
            {
                vol.Required(CONF_PROFILE_NAME, default=self.config_entry.title): PROFILE_NAME_SELECTOR,
                vol.Required(CONF_BASE_URL, default=suggested_base_url): URL_SELECTOR,
                vol.Required(CONF_ENTITIES, default=[]): ENTITY_SELECTOR,
                vol.Required(CONF_TAP_BEHAVIOR, default=DEFAULT_TAP_BEHAVIOR): TAP_BEHAVIOR_SELECTOR,
                vol.Required(CONF_AFTER_ACTION, default=DEFAULT_AFTER_ACTION): AFTER_ACTION_SELECTOR,
                vol.Required(CONF_SHOW_CONTROLS_ENTRY, default=DEFAULT_SHOW_CONTROLS_ENTRY): SHOW_CONTROLS_SELECTOR,
                vol.Required(CONF_STATE_WAIT, default=str(DEFAULT_STATE_WAIT)): STATE_WAIT_SELECTOR,
                vol.Optional(CONF_NEW_USERNAME): USERNAME_SELECTOR,
                vol.Optional(CONF_NEW_PASSWORD): PASSWORD_SELECTOR,
                vol.Optional(CONF_PHONE_URL, default=""): URL_SELECTOR,
                vol.Optional(CONF_PHONE_USERNAME): USERNAME_SELECTOR,
                vol.Optional(CONF_PHONE_PASSWORD): PASSWORD_SELECTOR,
                vol.Required(
                    CONF_PHONE_VERIFY_SSL,
                    default=current_options.get(CONF_PHONE_VERIFY_SSL, True),
                ): SHOW_CONTROLS_SELECTOR,
                vol.Required(CONF_PHONE_ACTIONS, default=list(DEFAULT_PHONE_ACTIONS)): PHONE_ACTION_SELECTOR,
            }
        )
        preview_base = _preview_base_url(suggested.get(CONF_BASE_URL))
        profile_id = _entry_profile_id(self.config_entry)
        current_username = str(self.config_entry.data.get(CONF_USERNAME, "<USERNAME>"))
        return self.async_show_form(
            step_id="init",
            data_schema=self.add_suggested_values_to_schema(schema, suggested),
            description_placeholders={
                "phone_url": _phone_url(preview_base, profile_id),
                "embedded_url_template": _embedded_auth_url_template(preview_base, profile_id, current_username),
                "suggested_base_url": suggested_base_url or "",
            },
            errors=errors,
        )
