"""Shared pytest fixtures for the IdP test suite."""

from collections.abc import Generator
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from faker import Faker
from flask.testing import FlaskClient
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.config import IdPConfig, SPConfig
from saml2.metadata import create_metadata_string
from saml2.server import Server

from idp.app import app as flask_app


def generate_key_pair() -> dict[str, str]:
    """Return a  certificate and private key."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([])

    # Now generate an X.509 certificate.
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before := datetime.now(timezone.utc))
        .not_valid_after(not_valid_before + timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )

    # Return the certificate and key in PEM format.
    return {
        "cert": cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
        "key": key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8"),
    }


@pytest.fixture
def client() -> Generator[FlaskClient, None, None]:
    """Provide a Flask test client."""
    flask_app.config.update({"TESTING": True})
    with flask_app.test_client() as client:
        yield client


@pytest.fixture
def mockSp_entityid(faker: Faker) -> str:
    """Uniquely identify a mock SAML 2.0 service provider."""
    return f"https://{faker.hostname()}/"


@pytest.fixture
def mockIdp_entityid(faker: Faker) -> str:
    """Uniquely identify a mock SAML 2.0 identity provider."""
    return f"https://{faker.hostname()}/"


@pytest.fixture
def mockSpConfig(
    mockSp_entityid: str, tmp_path_factory: pytest.TempPathFactory
) -> dict[str, Any]:
    """Generate configurations for the mock SP."""
    acs_url = f"{mockSp_entityid}/acs"
    slo_url = f"{mockSp_entityid}/slo"

    sp_keymat = generate_key_pair()
    cert_file = tmp_path_factory.getbasetemp() / "sp-cert.pem"
    with cert_file.open("w") as cf:
        cf.write(sp_keymat["cert"])
    key_file = tmp_path_factory.getbasetemp() / "sp-key.pem"
    with key_file.open("w") as kf:
        kf.write(sp_keymat["key"])
    return {
        "entityid": mockSp_entityid,
        "key_file": str(kf.name),
        "cert_file": str(cf.name),
        "service": {
            "sp": {
                "endpoints": {
                    "assertion_consumer_service": [(acs_url, BINDING_HTTP_POST)],
                    "single_logout_service": [(slo_url, BINDING_HTTP_POST)],
                }
            }
        },
    }


@pytest.fixture
def mockIdpConfig(
    mockIdp_entityid: str, tmp_path_factory: pytest.TempPathFactory
) -> dict[str, Any]:
    """Generate configurations for the mock IDP."""
    sso_url = f"{mockIdp_entityid}/sso"
    slo_url = f"{mockIdp_entityid}/slo"

    idp_keymat = generate_key_pair()
    cert_file = tmp_path_factory.getbasetemp() / "idp-cert.pem"
    with cert_file.open("w") as cf:
        cf.write(idp_keymat["cert"])
    key_file = tmp_path_factory.getbasetemp() / "idp-key.pem"
    with key_file.open("w") as kf:
        kf.write(idp_keymat["key"])
    return {
        "entityid": mockIdp_entityid,
        "key_file": str(kf.name),
        "cert_file": str(cf.name),
        "service": {
            "idp": {
                "endpoints": {
                    "single_sign_on_service": [
                        (sso_url, BINDING_HTTP_REDIRECT),
                        (sso_url, BINDING_HTTP_POST),
                    ],
                    "single_logout_service": [(slo_url, BINDING_HTTP_POST)],
                }
            }
        },
    }


@pytest.fixture
def mockSp_metadata(
    mockSpConfig: dict[str, Any], tmp_path_factory: pytest.TempPathFactory
) -> Path:
    """Generate metadata for a mock service provider (SP)."""
    sp_metadata = tmp_path_factory.getbasetemp() / "sp-metadata.xml"
    with sp_metadata.open("wb") as spm:
        spm.write(create_metadata_string(None, config=SPConfig().load(mockSpConfig)))

    return sp_metadata


@pytest.fixture
def mockIdp_metadata(
    mockIdpConfig: dict[str, Any], tmp_path_factory: pytest.TempPathFactory
) -> Path:
    """Generate metadata for a mock identity provider (IDP)."""
    idp_metadata = tmp_path_factory.getbasetemp() / "idp-metadata.xml"
    with idp_metadata.open("wb") as idpm:
        idpm.write(create_metadata_string(None, config=IdPConfig().load(mockIdpConfig)))
    return idp_metadata


@pytest.fixture
def mockIdp(mockIdpConfig: dict[str, Any], mockSp_metadata: Path) -> Server:
    """Provide an idp server for testing."""
    mockIdpConfig["metadata"] = {"local": [str(mockSp_metadata)]}
    return Server(config=IdPConfig().load(mockIdpConfig))


@pytest.fixture
def mockSp(mockSpConfig: dict[str, Any], mockIdp_metadata: Path) -> Saml2Client:
    """Provide an sp server for testing."""
    mockSpConfig["metadata"] = {"local": [str(mockIdp_metadata)]}
    return Saml2Client(config=SPConfig().load(mockSpConfig))


@pytest.fixture
def samlrequest(mockSp: Saml2Client, mockIdp: Server) -> str:
    """Provide a saml request from the sp test server."""
    request_id, binding, http_info = mockSp.prepare_for_negotiated_authenticate(
        entity_id=mockIdp.config.entityid,
        relay_state="hello123",
    )
    headers = dict(http_info["headers"])

    location = headers["Location"]

    query = parse_qs(urlparse(location).query)

    return query["SAMLRequest"][0]
