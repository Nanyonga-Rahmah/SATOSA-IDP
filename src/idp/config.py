"""SAML IdP configuration for the SATOSA test Identity Provider."""

from pathlib import Path

from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT

_PROJECT_ROOT: Path = Path(__file__).resolve().parents[0]

CONFIG: dict[str, object] = {
    "entityid": "http://localhost:9000/idp",
    "key_file": str(_PROJECT_ROOT / "certs" / "idp.key"),
    "cert_file": str(_PROJECT_ROOT / "certs" / "idp.crt"),
    "service": {
        "idp": {
            "endpoints": {
                "single_sign_on_service": [
                    (
                        "http://localhost:9000/sso",
                        BINDING_HTTP_REDIRECT,
                    ),
                    (
                        "http://localhost:9000/sso",
                        BINDING_HTTP_POST,
                    ),
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
            str(_PROJECT_ROOT / "metadata" / "sp-metadata.xml"),
            str(_PROJECT_ROOT / "metadata" / "saml-idp.xml"),
        ],
    },
}
