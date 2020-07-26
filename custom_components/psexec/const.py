import voluptuous as vol
import homeassistant.helpers.config_validation as cv

from homeassistant.const import (
    CONF_COMMAND,
    CONF_HOST,
    CONF_PASSWORD,
    CONF_USERNAME,
)

DOMAIN = "psexec"
CONF_INTERACTIVE = 'interactive'
CONF_KWARGS = 'kwargs'

COMPONENT_CONFIG_PSEXEC_CONNECTION = {
    vol.Required(CONF_HOST): cv.string,
    vol.Required(CONF_USERNAME): cv.string,
    vol.Required(CONF_PASSWORD): cv.string,
    vol.Required(CONF_COMMAND): cv.string,
    vol.Optional(CONF_INTERACTIVE, default=False): cv.boolean,
    vol.Optional(CONF_KWARGS, default="{}"): cv.string,
}
