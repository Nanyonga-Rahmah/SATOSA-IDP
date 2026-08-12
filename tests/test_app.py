from idp.app import create_saml_server ,authenticate_user
from idp.config import CONFIG


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
    session=create_session(user)
    assert session is not None

def test_unauthenticated_user_does_not_get_session():
    user = authenticate_user("rahmah", "wrong")
    session=create_session(user)
    assert session is None

def test_session_belongs_to_authenticated_user():
    user = authenticate_user("rahmah", "password123")
    session_id=create_session(user)
    assert get_session_user(session_id) == "rahmah"       
       
    
