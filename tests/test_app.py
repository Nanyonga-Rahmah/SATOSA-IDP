"""Tests for the IdP Flask application."""

from idp.app import authenticate_user


def test_metadata_returns_xml(client) -> None:
    """The metadata endpoint should return valid-looking XML."""
    response = client.get("/metadata")
    assert response.status_code == 200
    assert b"EntityDescriptor" in response.data


def test_authenticate_user_valid_credentials() -> None:
    """A correct username/password should return the user record."""
    user = authenticate_user("rahmah", "password123")
    assert user is not None
    assert user["mail"] == "rahmah@example.com"


def test_authenticate_user_wrong_password() -> None:
    """An incorrect password should return None."""
    assert authenticate_user("rahmah", "wrong") is None


def test_authenticate_user_unknown_username() -> None:
    """An unknown username should return None."""
    assert authenticate_user("nobody", "anything") is None


def test_login_rejects_unknown_user(client) -> None:
    """POSTing /login with a nonexistent user should return 401."""
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
    """POSTing /login with a wrong password should return 401."""
    with client.session_transaction() as sess:
        sess["saml_request"] = "dummy"
        sess["relay_state"] = "dummy"
        sess["sp_info"] = {}

    response = client.post(
        "/login",
        data={"username": "rahmah", "password": "wrong"},
    )
    assert response.status_code == 401
