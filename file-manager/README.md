# Secure File Encryption and Management

## Scope

[Design document](docs/DESIGN.md) · [Architecture diagram](docs/architecture.svg) · [Acceptance tests](../docs/ACCEPTANCE.md)

Only `/` and `/health/` work (GET and HEAD). Login and encryption are planned; the routes below return 404.

## Local run

Run from the repository root:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python file-manager/manage.py migrate
python file-manager/manage.py runserver 127.0.0.1:8000
```

Open <http://127.0.0.1:8000/>. SQLite stores its database here; Git ignores it. The development signing secret changes on restart. Export `DJANGO_SECRET_KEY` to keep sessions between restarts when login is added.

## Planned routes and features

| Method | Route | Purpose |
| --- | --- | --- |
| GET, POST | `/auth/register/` | Create an account after server-side validation |
| GET, POST | `/auth/login/` | Authenticate; rotate session identifier |
| POST | `/auth/logout/` | Invalidate session |
| GET | `/files/` | List only the signed-in user's file metadata |
| POST | `/files/upload/` | Validate, encrypt, and store a file |
| POST | `/files/<uuid>/download/` | Check owner, authenticate ciphertext, return attachment |
| POST | `/files/<uuid>/rename/` | Validate and change a display name |
| POST | `/files/<uuid>/delete/` | Delete an owned file |

POST requests require CSRF checks and permission checks on the server. GET never changes data. Downloads use POST as well.

## Verification

```sh
python file-manager/manage.py check
python file-manager/manage.py test core
```

Tests cover the starter. See [test results](../docs/VERIFICATION.md) and the [planned security tests](../docs/ACCEPTANCE.md).

## Deployment plan

Each app needs its own hostname, database, signing secret and service account. Caddy handles HTTPS and forwards to a WSGI server on loopback. Nothing is deployed yet.

Export the settings listed in `.env.example`; Django does not load that file automatically. Generate a random `DJANGO_SECRET_KEY` of at least 50 characters. Enable `TRUST_TLS_PROXY=1` only if the proxy overwrites the protocol header and direct backend access is blocked.
