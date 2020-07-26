import logging
import ast
import voluptuous as vol
import homeassistant.helpers.config_validation as cv
from homeassistant import core

from .const import (
    DOMAIN,
    CONF_HOST,
    CONF_USERNAME,
    CONF_PASSWORD,
    CONF_COMMAND,
    CONF_INTERACTIVE,
    CONF_KWARGS,
    COMPONENT_CONFIG_PSEXEC_CONNECTION,
)

_LOGGER = logging.getLogger(__name__)


def setup(hass: core.HomeAssistant, config: dict) -> bool:
    def _exec(call):
        from custom_components.psexec.PSExecAPI import PSExecAPI

        host = call.data.get(CONF_HOST)
        username = call.data.get(CONF_USERNAME)
        password = call.data.get(CONF_PASSWORD)
        command = call.data.get(CONF_COMMAND)
        if not all((host, username, password, command)):
            _LOGGER.error("Cannot psexec without host, username, password, command")
            return False

        interactive = call.data.get(CONF_INTERACTIVE, False)
        kwargs = call.data.get(CONF_KWARGS, {})
        if isinstance(kwargs, str):
            kwargs = ast.literal_eval(kwargs)

        _LOGGER.debug(f"""psexec:
host: {host}
username: {username}
password: {password}
command: {command}
interactive: {interactive}
kwargs: {type(kwargs)}
{kwargs}""")

        psexecapi = PSExecAPI.get(host, username, password)

        try:
            psexecapi.run_cmd(command, interactive, **kwargs)
        except:
            _LOGGER.exception(f"psexec failed on host {host}:")
        finally:
            psexecapi._destroy()

    hass.services.register(DOMAIN, 'exec', _exec, COMPONENT_CONFIG_PSEXEC_CONNECTION)
    return True

