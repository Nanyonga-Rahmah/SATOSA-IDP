from idp.app import create_saml_server
from idp.config import CONFIG


def test_idp_uses_configured_entity_id():
    server = create_saml_server()

    assert server.config.entityid == CONFIG["entityid"]

def test_idp_is_configured_correctly():
    server = create_saml_server()

    assert server.config.key_file == CONFIG["key_file"]
    assert server.config.cert_file == CONFIG["cert_file"] 


    
