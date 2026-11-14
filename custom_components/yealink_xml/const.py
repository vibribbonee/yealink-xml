"""Constants for the Yealink XML Browser integration."""

DOMAIN = "yealink_xml"
CONF_PROFILE_ID = "profile_id"
CONF_PROFILE_NAME = "profile_name"
CONF_ENTITIES = "entities"
CONF_TAP_BEHAVIOR = "tap_behavior"
CONF_AFTER_ACTION = "after_action"
CONF_SHOW_CONTROLS_ENTRY = "show_controls_entry"
CONF_STATE_WAIT = "state_wait"
CONF_BASE_URL = "base_url"
CONF_USERNAME = "username"
CONF_PASSWORD_HASH = "password_hash"
CONF_PASSWORD_SALT = "password_salt"
CONF_PHONE_URL = "phone_url"
CONF_PHONE_USERNAME = "phone_username"
CONF_PHONE_PASSWORD = "phone_password"
CONF_PHONE_VERIFY_SSL = "phone_verify_ssl"
CONF_PHONE_ACTIONS = "phone_actions"
SERVICE_PUSH_NOTIFICATION = "push_notification"
ATTR_PROFILE_ID = "profile_id"
ATTR_PHONE_ENTRY_ID = "phone"
ATTR_NOTIFICATION_TITLE = "title"
ATTR_NOTIFICATION_MESSAGE = "message"
ATTR_NOTIFICATION_BEEP = "beep"
ATTR_NOTIFICATION_RING = "ring"
ATTR_NOTIFICATION_TIMEOUT = "timeout"
CONF_NEW_USERNAME = "new_username"
CONF_NEW_PASSWORD = "new_password"
VIEW_PATH = "/api/yealink_xml"

ROOT_PAGE_SIZE = 24
ENTITY_PAGE_SIZE = 24
CHOICE_PAGE_SIZE = 12
MAX_XML_BYTES = 10_000

TAP_BEHAVIOR_MENU = "menu"
TAP_BEHAVIOR_DEFAULT = "default_action"
TAP_BEHAVIOR_TOGGLE = "toggle"
AFTER_ACTION_MENU = "menu"
AFTER_ACTION_ENTITY = "entity"
DEFAULT_TAP_BEHAVIOR = TAP_BEHAVIOR_DEFAULT
DEFAULT_AFTER_ACTION = AFTER_ACTION_MENU
DEFAULT_SHOW_CONTROLS_ENTRY = True
DEFAULT_STATE_WAIT = 2
# Some cloud-connected devices take several seconds to publish their updated
# state. Waiting is event-light and exits immediately when the state changes.
STATE_WAIT_OPTIONS = ("0", "0.5", "1", "1.5", "2", "3", "4", "5")

# Actions exposed as Home Assistant button entities for the configured phone.
PHONE_ACTIONS = {
    "dnd_on": ("DND on", "DNDOn"),
    "dnd_off": ("DND off", "DNDOff"),
    "back_idle": ("Return to idle screen", "BACK_IDLE"),
    "volume_up": ("Volume up", "VOLUME_UP"),
    "volume_down": ("Volume down", "VOLUME_DOWN"),
    "mute": ("Mute current call", "MUTE"),
    "message": ("Open messages", "MSG"),
    "headset": ("Headset key", "HEADSET"),
}
DEFAULT_PHONE_ACTIONS = ("dnd_on", "dnd_off")
