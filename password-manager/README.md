# Secure Password Manager

## Scope

[Design document](docs/DESIGN.md) · [Architecture diagram](docs/architecture.svg) · [Acceptance tests](../docs/ACCEPTANCE.md)

Only `/` and `/health/` work (GET and HEAD). Login and encryption are planned; the routes below return 404.

## Local run

Run from the repository root:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python password-manager/manage.py migrate
python password-manager/manage.py runserver 127.0.0.1:8001
```

Open <http://127.0.0.1:8001/>. SQLite stores its database here; Git ignores it. The development signing secret changes on restart. Export `DJANGO_SECRET_KEY` to keep sessions between restarts when login is added.

## Planned routes and features

| Method | Route | Purpose |
| --- | --- | --- |
| GET, POST | `/auth/register/` | Create account and initialize master-password vault |
| GET, POST | `/auth/login/` | Authenticate with account password; rotate session |
| POST | `/auth/logout/` | Invalidate session |
| GET | `/vault/entries/` | List opaque entry identifiers; no secret values |
| POST | `/vault/entries/create/` | Master password required; encrypt entry |
| POST | `/vault/entries/<uuid>/reveal/` | Master password required; decrypt owned entry |
| POST | `/vault/entries/<uuid>/update/` | Master password required; replace encrypted entry |
| POST | `/vault/entries/<uuid>/delete/` | Master password required; delete owned entry |
| POST | `/vault/master-password/` | Verify old master password and rewrap vault key |

POST requests require CSRF checks and permission checks on the server. GET never changes data. Revealing credentials also requires POST. Send master passwords in the request body, never the URL.

## Verification

```sh
python password-manager/manage.py check
python password-manager/manage.py test core
```

Tests cover the starter. See [test results](../docs/VERIFICATION.md) and the [planned security tests](../docs/ACCEPTANCE.md).

## Deployment plan

Each app needs its own hostname, database, signing secret and service account. Caddy handles HTTPS and forwards to a WSGI server on loopback. Nothing is deployed yet.

Export the settings listed in `.env.example`; Django does not load that file automatically. Generate a random `DJANGO_SECRET_KEY` of at least 50 characters. Enable `TRUST_TLS_PROXY=1` only if the proxy overwrites the protocol header and direct backend access is blocked.
