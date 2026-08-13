from pathlib import Path

from saml2.config import IdPConfig
from saml2.server import Server
from flask import Flask, render_template, request, session
from flask.typing import ResponseReturnValue
from .config import CONFIG


SESSIONS = {}
app = Flask(__name__)

PROJECT_ROOT: Path = Path(__file__).resolve().parents[0]


def create_saml_server():
    return Server(config=IdPConfig().load(CONFIG))

USERS=[{"username": "rahmah", "password": "password123"}]    

def authenticate_user(username: str, password: str):
    """Authenticate a user by checking their username and password."""
    for user in USERS:
        if user["username"] == username and user["password"] == password:
            return user
    return None

def create_session(user): 
    """Create a session for an authenticated user."""
    if user is None:
        return None
    session_id = f"session_{user['username']}"
    SESSIONS[session_id] = user
    return session_id  

def get_session_user(session_id):
    """Retrieve the user associated with a session ID."""
    user = SESSIONS.get(session_id)
    if user:
        return user["username"]
    return None   

@app.route("/metadata")
def metadata() -> ResponseReturnValue:
    """Serve this IdP's SAML metadata as XML."""
    with open(str(PROJECT_ROOT / "metadata" / "idp-metadata.xml")) as f:
        xml = f.read()

    return xml, 200, {"Content-Type": "application/xml"}      