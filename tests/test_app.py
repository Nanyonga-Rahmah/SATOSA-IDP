from flask import session

from idp.app import create_saml_server ,authenticate_user,create_session,get_session_user
from idp.config import CONFIG

from pytest import mark

VALID_SAML_REQUEST = """<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="ONELOGIN_809707f0030a5d00620c9d9df97f627afe9dcc24" Version="2.0" ProviderName="SP test" IssueInstant="2014-07-16T23:52:45Z" Destination="http://idp.example.com/SSOService.php" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="http://sp.example.com/demo1/index.php?acs">
  <saml:Issuer>http://sp.example.com/demo1/metadata.php</saml:Issuer>
  <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/>
  <samlp:RequestedAuthnContext Comparison="exact">
    <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
  </samlp:RequestedAuthnContext>
</samlp:AuthnRequest>"""
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

def test_sso_receives_a_samlrequest(client)->None:
    response = client.get("/sso", query_string={"SAMLRequest": "dummy"})
    assert response.status_code == 200

@mark.parametrize("saml_request ,expected_value",[
    (VALID_SAML_REQUEST, 200),
    (INVALID_SAML_REQUEST, 400)
])
def test_if_sso_receives_a_valid_samlrequest(client, saml_request, expected_value)->None:
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
    
