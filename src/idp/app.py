from saml2.config import IdPConfig
from saml2.server import Server

from .config import CONFIG


def create_saml_server():
    return Server(config=IdPConfig().load(CONFIG))