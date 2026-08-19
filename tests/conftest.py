"""Shared pytest fixtures for the IdP test suite."""

import pytest

from idp.app import app as flask_app
from idp.app import create_saml_server

@pytest.fixture
def client():
    """Provide a Flask test client."""
    flask_app.config.update({"TESTING": True})
    with flask_app.test_client() as client:
        yield client

@pytest.fixture
def server():
    return create_saml_server()







    

