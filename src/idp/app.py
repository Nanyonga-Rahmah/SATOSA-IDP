from pathlib import Path

from flask import Flask, render_template, request, session
from flask.typing import ResponseReturnValue
from saml2.authn_context import PASSWORDPROTECTEDTRANSPORT
from saml2.config import IdPConfig
from saml2.server import Server

from .config import CONFIG

SESSIONS = {}
app = Flask(__name__)
app.secret_key = "test-key"

PROJECT_ROOT: Path = Path(__file__).resolve().parents[0]


def create_saml_server():
    return Server(config=IdPConfig().load(CONFIG))


USERS = [{"username": "rahmah", "password": "password123"}]


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
        response = create_saml_server().parse_authn_request(saml_request)
        authn_request = response.message
        sp_info = create_saml_server().response_args(authn_request)
        session["sp_info"] = sp_info
        session["saml_request"] = saml_request
        session["relay_state"] = saml_relay_state

    except Exception:
        return "Invalid SAMLRequest", 400

    return render_template("login.html"), 200


@app.route("/login", methods=["POST"])
def login() -> ResponseReturnValue:
    """Authenticate the user and create a SAML response."""

    username = request.form.get("username")
    password = request.form.get("password")

    user = authenticate_user(username, password)

    if user is None:
        return "Invalid username or password", 401

    session_id = create_session(user)

    saml_request = session["saml_request"]
    relay_state = session["relay_state"]
    sp_info = session["sp_info"]

    parsed_request = create_saml_server().parse_authn_request(
        saml_request,
    )

    authn_request = parsed_request.message

    saml_response = create_saml_server().create_authn_response(
        authn={
            "class_ref": PASSWORDPROTECTEDTRANSPORT,
            "authn_auth": create_saml_server().config.entityid,
        },
        identity={
            "givenName": [user["username"]],
        },
        in_response_to=sp_info["in_response_to"],
        destination=sp_info["destination"],
        sp_entity_id=sp_info["sp_entity_id"],
        name_id_policy=sp_info["name_id_policy"],
        sign_response=True,
        sign_assertion=True,
        encrypt_assertion=False,
        encrypted_advice_attributes=False,
    )

    print(saml_response)
    http_info = create_saml_server().apply_binding(
        sp_info["binding"],
        str(saml_response),
        sp_info["destination"],
        relay_state=relay_state,
        response=True,
    )

    return str(http_info["data"])


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=9000)
