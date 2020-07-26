import logging

from homeassistant import core

from .const import (
    DOMAIN,
    CONF_HOST,
    CONF_USERNAME,
    CONF_PASSWORD,
    CONF_COMMAND,
    CONF_INTERACTIVE,
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
    COMPONENT_CONFIG_PSEXEC_CONNECTION,
)

consts = [
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

        interactive = call.data.get(CONF_INTERACTIVE, False)
        kwargs = {}
        for c in consts:
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
{str(kwargs)}""")

        psexecapi = PSExecAPI.get(host, username, password)

        try:
            psexecapi.run_cmd(cmd=command, interactively=interactive, **kwargs)
        except:
            _LOGGER.exception(f"psexec failed on host {host}:")
        finally:
            psexecapi._destroy()

    hass.services.register(DOMAIN, 'exec', _exec)
    # hass.services.register(DOMAIN, 'exec', _exec, COMPONENT_CONFIG_PSEXEC_CONNECTION)
    return True
