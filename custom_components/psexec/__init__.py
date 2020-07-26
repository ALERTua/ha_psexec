from homeassistant import core
import logging
import ast
import voluptuous as vol
import homeassistant.helpers.config_validation as cv

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


async def async_setup(hass: core.HomeAssistant, config: dict) -> bool:
    """Set up the PSExec API component."""
    def _exec(service):
        import uuid
        from custom_components.psexec.PSExecAPI import PSExecAPI

        host = service.data.get('host')
        username = service.data.get('username')
        password = service.data.get('password')
        command = service.data.get('command')
        if not all((host, username, password, command)):
            _LOGGER.error("Cannot psexec without host, username, password, command")
            return False

        interactive = service.data.get('interactive', False)
        kwargs = service.data.get('kwargs', {})
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

    hass.services.register(DOMAIN, 'exec', _exec)
    hass.services.async_register(
        DOMAIN,
        'exec',
        _exec,
        schema=COMPONENT_CONFIG_PSEXEC_CONNECTION,
    )
    return True
