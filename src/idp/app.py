"""Flask application for the SATOSA test Identity Provider."""

from pathlib import Path
from typing import cast

from flask import Flask, render_template, request, session
from flask.typing import ResponseReturnValue
from saml2 import BINDING_HTTP_REDIRECT
from saml2.authn_context import INTERNETPROTOCOLPASSWORD
from saml2.config import IdPConfig
from saml2.server import Server
from saml2.sigver import encrypt_cert_from_item

from .config import CONFIG

_PROJECT_ROOT: Path = Path(__file__).resolve().parents[0]

# ------------------------------------------------------------------
# Mock user database
# ------------------------------------------------------------------

USERS: dict[str, dict[str, str]] = {
    "rahmah": {
        "password": "password123",
        "givenName": "Rahmah",
        "sn": "Nanyonga",
        "mail": "rahmah@example.com",
    },
    "alice": {
        "password": "alice123",
        "givenName": "Alice",
        "sn": "Smith",
        "mail": "alice@example.com",
    },
    "john": {
        "password": "john123",
        "givenName": "John",
        "sn": "Doe",
        "mail": "john@example.com",
    },
}

app = Flask(__name__)
app.secret_key = "super-secret-key"

server = Server(config=IdPConfig().load(CONFIG))


@app.route("/metadata")
def metadata() -> ResponseReturnValue:
    """Serve this IdP's SAML metadata as XML."""
    with open(str(_PROJECT_ROOT / "metadata" / "idp-metadata.xml")) as f:
        xml = f.read()

    return xml, 200, {"Content-Type": "application/xml"}


@app.route("/sso", methods=["GET"])
def sso() -> ResponseReturnValue:
    """Handle an incoming AuthnRequest and show the login form."""
    saml_request = request.args.get("SAMLRequest")
    relay_state = request.args.get("RelayState")

    if not saml_request:
        return "Missing SAMLRequest", 400

    parsed_request = server.parse_authn_request(
        saml_request,
        BINDING_HTTP_REDIRECT,
    )

    authn_request = parsed_request.message
    sp_info = server.response_args(authn_request)

    session["saml_request"] = saml_request
    session["relay_state"] = relay_state
    session["sp_info"] = sp_info

    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login() -> ResponseReturnValue:
    """Authenticate the user and issue a signed SAML response."""
    username = request.form["username"]
    password = request.form["password"]

    user = USERS.get(username)

    if user is None:
        return (
            """
        <h2>Authentication Failed</h2>
        <p>User does not exist.</p>
        <a href="/sso">Try Again</a>
        """,
            401,
        )

    if user["password"] != password:
        return (
            """
        <h2>Authentication Failed</h2>
        <p>Incorrect password.</p>
        <a href="/sso">Try Again</a>
        """,
            401,
        )

    saml_request = session["saml_request"]
    relay_state = session["relay_state"]
    sp_info = session["sp_info"]

    parsed_request = server.parse_authn_request(
        saml_request,
        BINDING_HTTP_REDIRECT,
    )

    authn_request = parsed_request.message

    saml_response = server.create_authn_response(
        authn={
            "class_ref": INTERNETPROTOCOLPASSWORD,
            "authn_auth": server.config.entityid,
        },
        identity={
            "givenName": [user["givenName"]],
            "sn": [user["sn"]],
            "mail": [user["mail"]],
        },
        sign_response=True,
        sign_assertion=True,
        encrypt_assertion=False,
        encrypted_advice_attributes=False,
        encrypt_cert=encrypt_cert_from_item(authn_request),
        **sp_info,
    )

    http_args = server.apply_binding(
        sp_info["binding"],
        str(saml_response),
        sp_info["destination"],
        relay_state=relay_state,
        response=True,
    )

    return cast(str, http_args["data"])


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=9000)
