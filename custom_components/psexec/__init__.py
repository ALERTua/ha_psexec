import logging

from homeassistant import core
from homeassistant.const import CONF_HOST, CONF_USERNAME, CONF_PASSWORD, CONF_COMMAND

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

optionals = [
    CONF_ASYNCHRONOUS,
    CONF_LOAD_PROFILE,
    CONF_INTERACTIVE_SESSION,
    CONF_RUN_ELEVATED,
    CONF_RUN_LIMITED,
    CONF_USE_SYSTEM_ACCOUNT,
    CONF_WORKING_DIR,
    CONF_SHOW_UI_ON_WIN_LOGON,
    CONF_PRIORITY,
    CONF_REMOTE_LOG_PATH,
    CONF_TIMEOUT_SECONDS,
]

_LOGGER = logging.getLogger(__name__)


def setup(hass: core.HomeAssistant, config: dict) -> bool:
    def _exec(call):
        from custom_components.psexec.PSExecAPI import PSExecAPI

        host = call.data.get(CONF_HOST)
        username = call.data.get(CONF_USERNAME)
        password = call.data.get(CONF_PASSWORD)
        command = call.data.get(CONF_COMMAND)
        if all((host, username, password, command)):
            pass
        else:
            _LOGGER.error("Cannot psexec without host, username, password, command")
            return False

        interactive = call.data.get(CONF_INTERACTIVE, True)
        kwargs = {}
        for c in optionals:
            val = call.data.get(c)
            if val is not None:
                kwargs.update({c: val})

        _LOGGER.debug(f"""psexec:
host: {host}
username: {username}
password: {password}
command: {command}
interactive: {interactive}
kwargs:
{kwargs}""")

        # psexecapi = PSExecAPI.get(host, username, password)
        psexecapi = PSExecAPI(host, username, password)

        try:
            psexecapi.run_cmd(cmd=command, interactively=interactive, **kwargs)
        except:
            _LOGGER.exception(f"psexec failed on host {host}:")
        finally:
            psexecapi._destroy()

    hass.services.register(DOMAIN, 'exec', _exec)
    return True
