"""Shared pytest fixtures for the IdP test suite."""

from collections.abc import Generator
from pathlib import Path
from typing import Any, Dict
from urllib.parse import parse_qs, urlparse

import pytest
from flask.testing import FlaskClient
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.config import IdPConfig, SPConfig
from saml2.server import Server

from idp.app import app as flask_app

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_IDP_ROOT = _PROJECT_ROOT / "src" / "idp"
_SP_ROOT = _PROJECT_ROOT / "src" / "tests"


CONFIG: Dict[str, Any] = {
    # "entityid": "https://idp-latest.onrender.com/idp",
    "entityid": "http://127.0.0.1:9000",
    "key_file": str(_IDP_ROOT / "certs" / "idp.key"),
    "cert_file": str(_IDP_ROOT / "certs" / "idp.crt"),
    "service": {
        "idp": {
            "endpoints": {
                "single_sign_on_service": [
                    ("http://localhost:9000/sso", BINDING_HTTP_REDIRECT),
                    ("http://localhost:9000/sso", BINDING_HTTP_POST),
                ],
                "single_logout_service": [
                    ("http://localhost:9000/slo", BINDING_HTTP_REDIRECT),
                ],
            },
            "policy": {
                "default": {
                    "sign_response": True,
                    "sign_assertion": True,
                }
            },
        }
    },
    "metadata": {
        "local": [
            str(_IDP_ROOT / "metadata" / "sp-metadata.xml"),
            str(_IDP_ROOT / "metadata" / "saml-idp.xml"),
        ],
    },
}


SPCONFIG: Dict[str, Any] = {
    "entityid": "http://localhost:8000/metadata",
    "service": {
        "sp": {
            "endpoints": {
                "assertion_consumer_service": [
                    (
                        "http://localhost:8000/acs",
                        BINDING_HTTP_POST,
                    )
                ]
            },
            "allow_unsolicited": True,
            "want_assertions_signed": True,
            "authn_requests_signed": False,
        }
    },
    "key_file": str(_SP_ROOT / "certs" / "sp.key"),
    "cert_file": str(_SP_ROOT / "certs" / "sp.crt"),
    "metadata": {
        "local": [
            str(_SP_ROOT / "metadata" / "idp-metadata.xml"),
        ]
    },
    "debug": 1,
}


@pytest.fixture
def client() -> Generator[FlaskClient, None, None]:
    """Provide a Flask test client."""
    flask_app.config.update({"TESTING": True})
    with flask_app.test_client() as client:
        yield client


@pytest.fixture
def server() -> Server:
    """Provide an idp server for testing."""
    return Server(config=IdPConfig().load(CONFIG))


@pytest.fixture
def mockSp() -> Saml2Client:
    """Provide an sp server for testing"""
    return Saml2Client(config=SPConfig().load(SPCONFIG))


@pytest.fixture
def samlrequest(mockSp: Saml2Client, server: Server) -> str:
    """Provide a saml request from the sp test server"""
    request_id, binding, http_info = mockSp.prepare_for_negotiated_authenticate(
        entity_id=server.config.entityid,
        relay_state="hello123",
    )
    headers = dict(http_info["headers"])

    location = headers["Location"]

    query = parse_qs(urlparse(location).query)

    return query["SAMLRequest"][0]
