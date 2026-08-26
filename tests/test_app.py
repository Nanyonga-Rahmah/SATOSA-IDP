"""Tests for the Flask SAML identity provider."""

from typing import Any, Dict

from flask.testing import FlaskClient
from pytest import mark
from saml2.server import Server

from idp.app import (
    authenticate_user,
)

INVALID_SAML_REQUEST = "fake-" "request"
LOGOUT_REQUEST = (
    "nZLLbsIwEEV/JfIeGDshDwsioQIlKn3w6qI7J3EgUrBpxpFov"
    "74OSFS0FYvKi5FH9849I3ugEPhcb3VjlvK9kWic475SyG1/"
    "SJpacS2wtFexl8hNxlejxzlnXeCHWhud6YpcDPS2QSDK2pRaEScZD0mZdx4mwWy7WY8Wc"
    "zWd4mjySZxXWaOVDIl1WB1iIxOFRihjW8D8DoQdBmvKOFAO/"
    "htxxpa5VMKcXDtjDrzXq3Qmqp1GwyMA6GGlibOUAlsJiQcWlZ9G185U13thboO3HUtbn"
    "KRcKlOaDxL/igpt1KD3Pfuc82TNydhpy6IRVVmUsr5wUhZ0wR564iTO6uVv3XUI+Qe1qYXC0r"
    "KTOI9CmorQE2GRAYMwDcAr+jTwXJZlXl+AHwlGIae+G6Q+s8VjqRtGhesHfhCk5x3Pe7U7Al9"
    "JbB8tUbk8xjaTztwkie5nh3w7p8/bu01r+SE7t65+XvwF"
)
INLOGOUT_REQUEST = "fake-logout-request"


def test_idp_is_configured_correctly(
    mockIdp: Server, mockIdpConfig: Dict[str, Any]
) -> None:
    """Verify that the IdP uses the configured Saml Settings."""
    assert mockIdp.config.key_file == mockIdpConfig["key_file"]
    assert mockIdp.config.cert_file == mockIdpConfig["cert_file"]
    assert mockIdp.config.entityid == mockIdpConfig["entityid"]


def test_authenticate_valid_user() -> None:
    """Verify that user with correct credentials is correctly authenticated.

    and a response is returned
    """
    response = authenticate_user("rahmah", "password123")

    assert response is not None


def test_authenticate_invalid_user() -> None:
    """Verify that a user with incorrect credentials fails authentication."""
    response = authenticate_user("rahmah", "wrong")

    assert response is None


def test_authenticate_unknown_user() -> None:
    """Verify that a non-existent user fails authentication."""
    response = authenticate_user("nobody", "anything")

    assert response is None


def test_metadata_returns_xml(client: FlaskClient) -> None:
    """The metadata endpoint should return valid-looking XML."""
    response = client.get("/metadata")
    assert response.status_code == 200
    assert b"EntityDescriptor" in response.data


def test_sso_accepts_valid_saml_request(
    client: FlaskClient,
    samlrequest: str,
) -> None:
    """Verify that the sso endpoint  accepts a vlaid saml request."""
    response = client.get(
        "/sso",
        query_string={"SAMLRequest": samlrequest},
    )

    assert response.status_code == 200


def test_sso_rejects_invalid_saml_request(client: FlaskClient) -> None:
    """Verify that the sso endpoint rejects  invalid saml requests."""
    response = client.get(
        "/sso",
        query_string={"SAMLRequest": INVALID_SAML_REQUEST},
    )

    assert response.status_code == 400


def test_idp_creates_response_args_for_authn_request(
    mockIdp: Server, samlrequest: str
) -> None:
    """Verify that a valid saml request produces the required.

    response arguments
    """
    parsed_request = mockIdp.parse_authn_request(samlrequest)

    authn_request = parsed_request.message

    sp_info = mockIdp.response_args(authn_request)

    assert sp_info is not None


def test_sso_route_stores_saml_request_and_relay_state_in_session(
    client: FlaskClient, samlrequest: str, mockIdp: Server
) -> None:
    """Verify that the SSO route stores the SAML request and RelayState in the.

    session
    """
    relay_state = "dummy"
    response = mockIdp.parse_authn_request(samlrequest)
    authn_request = response.message
    sp_info = mockIdp.response_args(authn_request)

    with client.session_transaction() as session:
        session["saml_request"] == samlrequest
        session["relay_state"] == relay_state
        session["sp_info"] == sp_info

    response = client.get(
        "/sso",
        query_string={"SAMLRequest": samlrequest, "RelayState": relay_state},
    )

    assert response.status_code == 200

    assert session["saml_request"] is not None
    assert session["relay_state"] is not None
    assert session["sp_info"] is not None


def test_sso_route_does_not_create_session_for_invalid_requests(
    client: FlaskClient,
) -> None:
    """An invalid SAMLRequest should return a 400 response and not create a.

    session.
    """
    response = client.get(
        "/sso",
        query_string={"SAMLRequest": INVALID_SAML_REQUEST},
    )
    assert response.status_code == 400


def test_login_route_returns_401_for_invalid_credentials(
    client: FlaskClient, samlrequest: str, mockIdp: Server
) -> None:
    """An unsuccessful login should return a 401 response and not create a.

    SAML response
    """
    parsed_request = mockIdp.parse_authn_request(
        samlrequest,
    )

    authn_request = parsed_request.message

    sp_info = mockIdp.response_args(authn_request)

    with client.session_transaction() as session:
        session["saml_request"] = samlrequest
        session["relay_state"] = "dummy"
        session["sp_info"] = sp_info

    response = client.post(
        "/login",
        data={
            "username": "rahmah",
            "password": "wrongpassword",
        },
    )

    assert response.status_code == 401


def test_login_creates_a_response_for_authenticated_user_and_applies_binding(
    client: FlaskClient, samlrequest: str, mockIdp: Server
) -> None:
    """A successful login should create a SAML response and apply the correct.

    binding
    """
    parsed_request = mockIdp.parse_authn_request(
        samlrequest,
    )

    authn_request = parsed_request.message

    sp_info = mockIdp.response_args(authn_request)

    with client.session_transaction() as session:
        session["saml_request"] = samlrequest
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

    assert "SAMLResponse" in response_data

    assert "<form" in response_data


def test_whether_the_slo_route_receives_a_saml_logout_request(
    client: FlaskClient,
) -> None:
    """Verify that the slo route accepts a saml logout.

    request
    """
    response = client.get("/slo", query_string={"SAMLRequest": LOGOUT_REQUEST})
    assert response.status_code == 200


def test_slo_rejects_request_without_saml_request(client: FlaskClient) -> None:
    """Verify that the slo route rejects requests without saml logout.

    requests
    """
    response = client.get("/slo")
    assert response.status_code == 400


@mark.parametrize(
    "saml_request ,expected_value",
    [(LOGOUT_REQUEST, 200), (INLOGOUT_REQUEST, 400)],
)
def test_slo_validates_saml_requests(
    client: FlaskClient, saml_request: str, expected_value: int
) -> None:
    """Verify that the SLO endpoint validates SAML logout requests."""
    response = client.get("/slo", query_string={"SAMLRequest": saml_request})
    assert response.status_code == expected_value


def test_slo_route_clears_user_session(client: FlaskClient) -> None:
    """Verify that the SLO endpoint clears the user's session."""
    with client.session_transaction() as session:
        session["user"] = "testuser"

    response = client.get(
        "/slo",
        query_string={"SAMLRequest": LOGOUT_REQUEST},
    )

    assert response.status_code == 200

    with client.session_transaction() as session:
        assert "user" not in session


def test_slo_route_returns_logout_response(client: FlaskClient) -> None:
    """Verify that the SLO endpoint returns a SAML logout response."""
    response = client.get(
        "/slo",
        query_string={"SAMLRequest": LOGOUT_REQUEST},
    )

    assert response.status_code == 200
    assert 'name="SAMLResponse"' in response.data.decode()


def test_slo_route_applies_binding(client: FlaskClient) -> None:
    """Verify that the SLO endpoint returns the logout response using.

    the expected binding.
    """
    response = client.get(
        "/slo",
        query_string={"SAMLRequest": LOGOUT_REQUEST},
    )

    assert response.status_code == 200
    assert "<form" in response.data.decode()
