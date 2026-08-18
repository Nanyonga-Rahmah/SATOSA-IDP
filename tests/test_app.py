from flask import session

from idp.app import create_saml_server ,authenticate_user,create_session,get_session_user
from idp.config import CONFIG

from pytest import mark

VALID_SAML_REQUEST = "fVHLTsMwEPwVy/cQJ6LQrpJIgQqoVETUhB56M6lLLSV28W54fT1OykNIVY47mtmZnU0MCsg72puVeukUEntvG4Pg4ZR3zoCVqP0oW4VANZT5/RLiMwEHZ8nWtuG/gmhcIBGVI20NZ4t5yvU2aMVs7fJd/Da5dctN/DnnbK0cekrKvcLzEDu1MEjSkIdEfBGIaRCdV5GAyQyiyw1nc59ZG0mDak90gDBsbC2bvUWCmRAiRLScFd95r7TZavM8nvXpSEK4q6oiKB7KirP8J/+1Ndi1ypXKvepaPa6WJ4ynvbGskWeJbwaGSxy7sa6VNO7dI76c3UAFZUjTB89OGiTh3+6sH/6/MvsC"
INVALID_SAML_REQUEST = "fake-request"
FAKE_SAML_RESPONSE = "fake-response"

def test_idp_uses_configured_entity_id():
    server = create_saml_server()

    assert server.config.entityid == CONFIG["entityid"]

def create_valid_saml_response():
    server = create_saml_server()

    parsed_request = server.parse_authn_request(
        VALID_SAML_REQUEST,
    )

    authn_request = parsed_request.message
    sp_info = server.response_args(authn_request)

    response = server.create_authn_response(
        identity={
            "givenName": ["Rahmah"],
            "sn": ["Nanyonga"],
            "mail": ["rahmah@example.com"],
        },
        sign_response=True,
        sign_assertion=True,
        encrypt_assertion=False,
        **sp_info,
    )

    print("Created SAML Response:", response)

    return response    

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



@mark.parametrize("saml_request ,expected_value",[
    (VALID_SAML_REQUEST, 200),
    (INVALID_SAML_REQUEST, 400)
])
def test_sso_validates_saml_requests(client, saml_request, expected_value)->None:
    response = client.get("/sso", query_string={"SAMLRequest": saml_request})
    assert response.status_code == expected_value

def test_idp_creates_response_args_for_authn_request():
    server = create_saml_server()

    parsed_request = server.parse_authn_request(
        VALID_SAML_REQUEST
    )

    authn_request = parsed_request.message

    sp_info = server.response_args(authn_request)

    assert sp_info is not None

    
def test_sso_route_stores_saml_request_and_relay_state_in_session(client):
    saml_request = VALID_SAML_REQUEST
    relay_state = "dummy"
    response = create_saml_server().parse_authn_request(saml_request)
    authn_request = response.message
    sp_info = create_saml_server().response_args(authn_request)


    response = client.get(
        "/sso",
        query_string={"SAMLRequest": saml_request, "RelayState": relay_state},
    )

    assert response.status_code == 200

    with client.session_transaction() as session:
        assert session["saml_request"] == saml_request
        assert session["relay_state"] == relay_state
        assert session["sp_info"] == sp_info

   

# def test_login_authenticates_a_user_and_creates_a_session(client) -> None:
#     """A successful login should return a 200K response and create a session for the user."""
#     server = create_saml_server()
#     parsed_request = server.parse_authn_request(
#             VALID_SAML_REQUEST,
#         )
#     authn_request = parsed_request.message
#     sp_info = server.response_args(authn_request)

#     with client.session_transaction() as session:
#         session["saml_request"] = VALID_SAML_REQUEST
#         session["relay_state"] = "dummy"
      
#         session["sp_info"] = sp_info
       
#     response = client.get(
#         "/sso",
    
#     )
#     assert response.status_code == 200
#     assert b"Session ID:" in response.data

def test_sso_route_does_not_create_session_for_invalid_requests(client) -> None:
    """An invalid SAMLRequest should return a 400 response and not create a session."""
    response = client.get(
        "/sso",
        query_string={"SAMLRequest": INVALID_SAML_REQUEST},
    )
    assert response.status_code == 400

def test_login_route_authenticates_a_user_and_creates_response_for_valid_credentials(client) -> None:
    """A successful login should return a 200 response and create a SAML response."""
    server = create_saml_server()

    parsed_request = server.parse_authn_request(
        VALID_SAML_REQUEST,
    )

    authn_request = parsed_request.message

    sp_info = server.response_args(authn_request)

    with client.session_transaction() as session:
        session["saml_request"] = VALID_SAML_REQUEST
        session["relay_state"] = "dummy"
        session["sp_info"] = sp_info

    response = client.post(
        "/login",
        data={
            "username": "rahmah",
            "password": "password123",
        },
    )

    assert response.status_code == 200

    response_data = response.data.decode()

    assert "Response" in response_data
    assert sp_info["in_response_to"] in response_data
    assert sp_info["sp_entity_id"] in response_data
    assert sp_info["destination"] in response_data    

    
   

    