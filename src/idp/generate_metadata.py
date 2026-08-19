from pathlib import Path

from config import CONFIG
from saml2.config import IdPConfig
from saml2.metadata import create_metadata_string

_PROJECT_ROOT: Path = Path(__file__).resolve().parents[0]


metadata = create_metadata_string(
    None,
    config=IdPConfig().load(CONFIG),
)

with open("metadata/idp-metadata.xml", "wb") as f:
    f.write(metadata)
