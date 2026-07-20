"""Tests for the IdP Flask application."""


def test_metadata_returns_xml(client) -> None:
    """The metadata endpoint should return valid-looking XML."""
    response = client.get("/metadata")
    assert response.status_code == 200
    assert b"EntityDescriptor" in response.data


def test_login_rejects_unknown_user(client) -> None:
    """Logging in with a nonexistent user should return 401."""
    with client.session_transaction() as sess:
        sess["saml_request"] = "dummy"
        sess["relay_state"] = "dummy"
        sess["sp_info"] = {}

    response = client.post(
        "/login",
        data={"username": "nonexistent", "password": "wrong"},
    )
    assert response.status_code == 401


def test_login_rejects_wrong_password(client) -> None:
    """Logging in with a wrong password should return 401."""
    with client.session_transaction() as sess:
        sess["saml_request"] = "dummy"
        sess["relay_state"] = "dummy"
        sess["sp_info"] = {}

    response = client.post(
        "/login",
        data={"username": "rahmah", "password": "wrong"},
    )
    assert response.status_code == 401
