# SATOSA Test Identity Provider

A minimal SAML 2.0 Identity Provider (IdP) used for testing a local
SATOSA proxy deployment. Built with Flask and pysaml2, backed by a
mock in-memory user database.

## Requirements

- Python 3.11+
- `libxml2-dev`, `libxmlsec1-dev`, `libxmlsec1-openssl`, `pkg-config`
  (system packages required to build `pysaml2`)

On Debian/Ubuntu:

```sh
sudo apt-get install -y libxml2-dev libxmlsec1-dev \
    libxmlsec1-openssl pkg-config
```

## Project Structure

```text
idp/
├── src/
│   └── idp/
│       ├── __init__.py
│       ├── app.py              # Flask application and routes
│       └── config.py           # pysaml2 IdP configuration
├── certs/                      # IdP signing certificate/key
├── metadata/                   # SAML metadata (SP, SATOSA backend)
├── templates/                  # Flask HTML templates (login form)
├── tests/
├── pyproject.toml
├── GNUmakefile
└── .pre-commit-config.yaml
```

## Setup

Clone the repository, then run:

## Local Deployment

Follow these steps to run the IdP locally.

### 1. Clone the repository

```sh
git clone <repository-url>
cd SATOSA-IDP
```

### 2. Install Dependencies

```sh
sudo apt-get update

sudo apt-get install -y \
    libxml2-dev \
    libxmlsec1-dev \
    libxmlsec1-openssl \
    pkg-config
```


### 3.Setup Python Environment

```sh
make setup
```
```sh
source .venv/bin/activate
```

### 4.Start the idp

```sh
make run
```
This will run the idp on `http://localhost:9000` verify on `http://localhost:9000/metadata`

### 5.Run the tests
 ```sh
 make test
 ```



This creates a virtual environment, installs the package in
editable mode with development dependencies, and installs the
pre-commit hooks.

## Running the IdP

Start the Flask development server:

```sh
make run
```

The app listens on `http://localhost:9000` with the following
routes:

- `/metadata` — serves this IdP's SAML metadata
- `/sso` — receives an AuthnRequest and shows the login form
- `/login` — validates credentials and issues a signed SAML
  response back to the requesting SP or proxy

## Test Users

A mock in-memory user database is defined in `src/idp/app.py`:

| Username | Password      |
|----------|---------------|
| rahmah   | password123   |




## Configuration

SAML settings (entity ID, signing certificates, endpoints, and
trusted metadata) are defined in `src/idp/config.py`. Certificates
are expected at `certs/idp.key` and `certs/idp.crt`. Trusted SP/
proxy metadata is read from `metadata/`, and must include the
metadata of any SATOSA proxy backend or SP that will send this IdP
an `AuthnRequest`.



## Development

Format code:

```sh
make format
```

Lint and type-check:

```sh
make lint
```

Run tests:

```sh
make test
```

Pre-commit hooks run automatically on `git commit` and enforce
formatting, linting, and
[Conventional Commits](https://www.conventionalcommits.org/)
message style. To run all hooks manually against the full
codebase:

```sh
.venv/bin/pre-commit run --all-files
```