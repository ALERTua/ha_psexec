import voluptuous as vol
import homeassistant.helpers.config_validation as cv

from homeassistant.const import (
    CONF_COMMAND,
    CONF_HOST,
    CONF_PASSWORD,
    CONF_USERNAME,
)

DOMAIN = "psexec"
CONF_ASYNCHRONOUS = 'asynchronous'
CONF_LOAD_PROFILE = 'load_profile'
CONF_INTERACTIVE_SESSION = 'interactive_session'
CONF_INTERACTIVE = 'interactive'
CONF_RUN_ELEVATED = 'run_elevated'
CONF_RUN_LIMITED = 'run_limited'
CONF_USE_SYSTEM_ACCOUNT = 'use_system_account'
CONF_WORKING_DIR = 'working_dir'
CONF_SHOW_UI_ON_WIN_LOGON = 'show_ui_on_win_logon'
CONF_PRIORITY = 'priority'
CONF_REMOTE_LOG_PATH = 'remote_log_path'
CONF_TIMEOUT_SECONDS = 'timeout_seconds'

COMPONENT_CONFIG_PSEXEC_CONNECTION = {
    vol.Required(CONF_HOST): cv.string_with_no_html,
    vol.Required(CONF_USERNAME): cv.string_with_no_html,
    vol.Required(CONF_PASSWORD): cv.string_with_no_html,
    vol.Required(CONF_COMMAND): cv.string,
    vol.Optional(CONF_INTERACTIVE, default=False): cv.boolean,
    vol.Optional(CONF_ASYNCHRONOUS, default=False): cv.boolean,
    vol.Optional(CONF_LOAD_PROFILE, default=True): cv.boolean,
    vol.Optional(CONF_INTERACTIVE_SESSION, default=True): cv.positive_int,  # yes, a boolean as a default
    vol.Optional(CONF_RUN_ELEVATED, default=False): cv.boolean,
    vol.Optional(CONF_RUN_LIMITED, default=False): cv.boolean,
    vol.Optional(CONF_USE_SYSTEM_ACCOUNT, default=False): cv.boolean,
    vol.Optional(CONF_WORKING_DIR, default=""): cv.string_with_no_html,
    vol.Optional(CONF_SHOW_UI_ON_WIN_LOGON, default=False): cv.boolean,
    vol.Optional(CONF_REMOTE_LOG_PATH, default=""): cv.string_with_no_html,
    vol.Optional(CONF_TIMEOUT_SECONDS, default=0): cv.positive_int,
}
