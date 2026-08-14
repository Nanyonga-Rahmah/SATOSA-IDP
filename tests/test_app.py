from flask import session

from idp.app import create_saml_server ,authenticate_user,create_session,get_session_user
from idp.config import CONFIG

from pytest import mark

VALID_SAML_REQUEST = "fVHLTsMwEPwVy/cQJ6LQrpJIgQqoVETUhB56M6lLLSV28W54fT1OykNIVY47mtmZnU0MCsg72puVeukUEntvG4Pg4ZR3zoCVqP0oW4VANZT5/RLiMwEHZ8nWtuG/gmhcIBGVI20NZ4t5yvU2aMVs7fJd/Da5dctN/DnnbK0cekrKvcLzEDu1MEjSkIdEfBGIaRCdV5GAyQyiyw1nc59ZG0mDak90gDBsbC2bvUWCmRAiRLScFd95r7TZavM8nvXpSEK4q6oiKB7KirP8J/+1Ndi1ypXKvepaPa6WJ4ynvbGskWeJbwaGSxy7sa6VNO7dI76c3UAFZUjTB89OGiTh3+6sH/6/MvsC"
INVALID_SAML_REQUEST = "fake-request"

def test_idp_uses_configured_entity_id():
    server = create_saml_server()

    assert server.config.entityid == CONFIG["entityid"]

def test_idp_is_configured_correctly():
    server = create_saml_server()

    assert server.config.key_file == CONFIG["key_file"]
    assert server.config.cert_file == CONFIG["cert_file"] 

def test_authenticate_valid_user():
    response =authenticate_user("rahmah", "password123")

    assert response is not None

def test_authenticate_invalid_user():
    response = authenticate_user("rahmah", "wrong")

    assert response is None

def test_authenticate_unknown_user():
    response = authenticate_user("nobody", "anything")

    assert response is None    

def test_authenticated_user_gets_session():
    user = authenticate_user("rahmah", "password123")
    session_id=create_session(user)
    assert session_id is not None

def test_unauthenticated_user_does_not_get_session():
    user = authenticate_user("rahmah", "wrong")
    session_id=create_session(user)
    assert session_id is None

def test_session_belongs_to_authenticated_user():
    user = authenticate_user("rahmah", "password123")
    session_id=create_session(user)
    assert get_session_user(session_id) == "rahmah"       

def test_metadata_returns_xml(client) -> None:
    """The metadata endpoint should return valid-looking XML."""
    response = client.get("/metadata")
    assert response.status_code == 200
    assert b"EntityDescriptor" in response.data    

def test_sso_rejects_invalid_samlrequest(client) -> None:
    response = client.get(
        "/sso",
        query_string={"SAMLRequest": "dummy"}
    )

    assert response.status_code == 400

@mark.parametrize("saml_request ,expected_value",[
    (VALID_SAML_REQUEST, 200),
    (INVALID_SAML_REQUEST, 400)
])
def test_sso_validates_saml_requests(client, saml_request, expected_value)->None:
    response = client.get("/sso", query_string={"SAMLRequest": saml_request})
    assert response.status_code == expected_value

   

def test_login_authenticates_a_user_and_creates_a_session(client) -> None:
    """A successful login should return a 200K response and create a session for the user."""
    with client.session_transaction() as session:
        session["saml_request"] = "dummy"
        session["relay_state"] = "dummy"
        session["sp_info"] = {}

    response = client.post(
        "/login",
        data={"username": "rahmah", "password": "password123"},
    )
    assert response.status_code == 200
    
