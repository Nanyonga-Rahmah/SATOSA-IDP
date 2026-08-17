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


@app.route("/sso", methods=["GET"])
def sso() -> ResponseReturnValue:
    """Handle an incoming SAML authentication request."""

    saml_request = request.args.get("SAMLRequest")
    saml_relay_state = request.args.get("RelayState")

    if not saml_request:
        return "Missing SAMLRequest", 400

    try:
        response = create_saml_server().parse_authn_request(
            saml_request
        )
        sp_info = create_saml_server().response_args(authn_request)

    except Exception:
        return "Invalid SAMLRequest", 400

    return render_template("login.html"), 200

       
    


@app.route("/login", methods=["POST"])
def login() -> ResponseReturnValue:
    """Handle user login and create a session if credentials are valid."""
    username = request.form.get("username")
    password = request.form.get("password")

    user = authenticate_user(username, password)
    if user:
        session_id = create_session(user)
        return f"Login successful. Session ID: {session_id}", 200
    else:
        return "Invalid username or password", 401


if __name__ == "__main__":
     app.run(debug=True, host="0.0.0.0", port=9000)

       
      