from saml2.config import IdPConfig
from saml2.server import Server

from .config import CONFIG


def create_saml_server():
    return Server(config=IdPConfig().load(CONFIG))

USERS=[{"username": "rahmah", "password": "password123"}]    

def authenticate_user(username: str, password: str):
    """Authenticate a user by checking their username and password."""
    for user in USERS:
        if user["username"] == username and user["password"] == password:
            return user
    return None