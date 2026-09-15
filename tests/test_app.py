"""Tests for the Flask SAML identity provider."""

from pathlib import Path
from typing import Any, Dict
from urllib.parse import parse_qs, urlparse

from faker import Faker
from saml2.client import Saml2Client
from saml2.server import Server

from idp.app import create_saml_server, validate_request

faker = Faker()


def test_idp_creation(mockIdpConfig: dict[str, Any], mockSp_metadata: Path) -> None:
    """Test that create idp function creates an idp server given configuration data."""
    mockIdpConfig["metadata"] = {"local": [str(mockSp_metadata)]}
    idpServer = create_saml_server(mockIdpConfig)
    assert idpServer is not None
    assert isinstance(idpServer, Server)


def test_idp_is_configured_correctly(
    mockIdpConfig: Dict[str, Any], mockSp_metadata: Path
) -> None:
    """Verify that the created IdP uses the configured Saml Settings."""
    mockIdpConfig["metadata"] = {"local": [str(mockSp_metadata)]}
    idpServer = create_saml_server(mockIdpConfig)
    assert idpServer.config.key_file == mockIdpConfig["key_file"]
    assert idpServer.config.cert_file == mockIdpConfig["cert_file"]
    assert idpServer.config.entityid == mockIdpConfig["entityid"]
    assert idpServer.config.metadata is not None


def test_idp_validates_incoming_request(
    mockIdpConfig: Dict[str, Any],
    mockSp_metadata: Path,
    mockSp: Saml2Client,
    mockIdp_metadata: Path,
) -> None:
    """Verify that a created Idp authenticates a saml request."""
    mockIdpConfig["metadata"] = {"local": [str(mockSp_metadata)]}
    idpServer = create_saml_server(mockIdpConfig)
    reqid, http_info = mockSp.prepare_for_authenticate(
        entityid=mockIdpConfig["entityid"], relay_state=f"{faker.word()}"
    )
    headers = dict(http_info["headers"])
    redirect_url = headers["Location"]
    parsed_url = urlparse(redirect_url)
    query_params = parse_qs(parsed_url.query)
    saml_request = query_params.get("SAMLRequest", [None])[0]
    validated_request = validate_request(saml_request, idpServer)
    assert validated_request is not None
    assert validated_request.message.issuer.text == mockSp.config.entityid
    assert validated_request.message.destination in validated_request.receiver_addrs
